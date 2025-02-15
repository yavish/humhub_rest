<?php
/**
 * @link https://www.humhub.org/
 * @copyright Copyright (c) 2019 HumHub GmbH & Co. KG
 * @license https://www.humhub.com/licences
 */

namespace humhub\modules\rest\controllers\auth;

use Firebase\JWT\JWT;
use humhub\modules\rest\components\BaseController;
use humhub\modules\rest\definitions\UserDefinitions;
use humhub\modules\rest\models\ImpersonateAuthToken;
use humhub\modules\rest\models\JwtAuthForm;
use humhub\modules\user\models\forms\Login;
use humhubContrib\auth\wechat\authclient\WechatAuth;
use humhub\modules\user\models\User;
use humhub\modules\user\services\AuthClientService;
use Yii;
use yii\web\ForbiddenHttpException;
use yii\web\JsonParser;
use yii\web\NotFoundHttpException;

class AuthController extends BaseController
{
    public function beforeAction($action)
    {
        if (in_array($action->id, ['current', 'impersonate'])) {
            return parent::beforeAction($action);
        }

        Yii::$app->response->format = 'json';
        Yii::$app->request->setBodyParams(null);
        Yii::$app->request->parsers['application/json'] = JsonParser::class;

        return true;
    }

    public function actionIndex()
    {
        $user = static::authByUserAndPassword(Yii::$app->request->post('username'), Yii::$app->request->post('password'));

        if ($user === null) {
            return $this->returnError(400, 'Wrong username or password');
        }

        if (!$this->isUserEnabled($user)) {
            return $this->returnError(401, 'Invalid user!');
        }

        $issuedAt = time();
        $data = [
            'iat' => $issuedAt,
            'iss' => Yii::$app->settings->get('baseUrl'),
            'nbf' => $issuedAt,
            'uid' => $user->id,
            'email' => $user->email
        ];

        $config = JwtAuthForm::getInstance();
        if (!empty($config->jwtExpire)) {
            $data['exp'] = $issuedAt + (int)$config->jwtExpire;
        }

        $jwt = JWT::encode($data, $config->jwtKey, 'HS512');

        return $this->returnSuccess('Success', 200, [
            'auth_token' => $jwt,
            'expired_at' => (!isset($data['exp'])) ? 0 : $data['exp']
        ]);
    }



    public static function authByUserAndPassword($username, $password)
    {
        $login = new Login;
        if (!$login->load(['username' => $username, 'password' => $password], '') || !$login->validate()) {
            return null;
        }

        $user = (new AuthClientService($login->authClient))->getUser();
        return $user;
    }

    /**
     * Get current User details
     *
     * @return array
     */
    public function actionCurrent()
    {
        $user = User::findOne(['id' => Yii::$app->user->id]);
        if ($user === null) {
            return $this->returnError(404, 'User not found!');
        }

        return UserDefinitions::getUser($user);
    }

    public function actionImpersonate()
    {
        if (!Yii::$app->user->isAdmin()) {
            throw new ForbiddenHttpException();
        }

        $user = User::findOne(['id' => Yii::$app->request->getBodyParam('userId')]);

        if ($user === null) {
            throw new NotFoundHttpException();
        }

        if ($token = ImpersonateAuthToken::findOne(['user_id' => $user->id])) {
            $token->delete();
        }

        $token = new ImpersonateAuthToken();
        $token->user_id = $user->id;
        $token->save();
        $token->refresh();

        return [
            'token' => $token->token,
            'expires' => strtotime($token->expiration),
        ];
    }


    // HumHub 后端登录接口
    public function actionWechatLogin()
    {
       
        $client = new WechatAuth();
        // Get the access_token and save them to the session.
         if (($code = Yii::$app->request->post('code')) !== null) {
            $token = $client->fetchAccessToken($code);
            if (!empty($token)) {
                return $this->authSuccess($client);
            }
            return $this->returnError(401, 'wechat auth fail!');
         
        }
        return $this->returnError(401, 'code is null');
        
    }


    // 获取微信 session 信息
    private function getWechatSession($code)
    {
        //楼码云微信小程序
        $appId = 'wxe9ebc38a3ba8d886';
        $appSecret = '499008a7889712377525554c8a816fb8';
        $url = "https://api.weixin.qq.com/sns/jscode2session?appid={$appId}&secret={$appSecret}&js_code={$code}&grant_type=authorization_code";

        $response = file_get_contents($url);
        return json_decode($response, true);
    }

    /**
     * Handle successful authentication
     *
     * @param BaseClient $authClient
     * @return Response
     * @throws Throwable
     */
    public function authSuccess(BaseClient $authClient)
    {
        // // User already logged in - Add new authclient to existing user
        // if (!Yii::$app->user->isGuest) {
        //     Yii::$app->user->getAuthClientUserService()->add($authClient);
        //     //return $this->redirect(['/user/account/connected-accounts']);
        // }

        $authClientService = new AuthClientService($authClient);
        $authClientService->autoMapToExistingUser();

        $user = $authClientService->getUser();

        if ($user === null) {
            return $this->returnError(400, 'Wrong username or password');
        }

        if (!$this->isUserEnabled($user)) {
            return $this->returnError(401, 'Invalid user!');
        }

        $issuedAt = time();
        $data = [
            'iat' => $issuedAt,
            'iss' => Yii::$app->settings->get('baseUrl'),
            'nbf' => $issuedAt,
            'uid' => $user->id,
            'email' => $user->email
        ];

        $config = JwtAuthForm::getInstance();
        if (!empty($config->jwtExpire)) {
            $data['exp'] = $issuedAt + (int)$config->jwtExpire;
        }

        $jwt = JWT::encode($data, $config->jwtKey, 'HS512');

        return $this->returnSuccess('Success', 200, [
            'auth_token' => $jwt,
            'expired_at' => (!isset($data['exp'])) ? 0 : $data['exp']
        ]);



       
    }

    

}
