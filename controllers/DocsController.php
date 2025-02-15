<?php
/**
 * @link https://www.humhub.org/
 * @copyright Copyright (c) 2018 HumHub GmbH & Co. KG
 * @license https://www.humhub.com/licences
 */

// protected/modules/rest/controllers/DocsController.php
namespace humhub\modules\rest\controllers;

use Yii;
use yii\web\Controller;

class DocsController extends Controller
{
	public function actionIndex()
    {
        return $this->renderFile('@app/modules/rest/docs/html/index.html');
    }
    public function actionPage($page)
    {
		$page = $page ? $page: 'index.html';
        return $this->renderFile('@app/modules/rest/docs/html/'.$page);
    }

	public function actionModule($module)
    {
		
        return $this->renderFile('@app/modules/'.$module.'/docs/swagger/'.$module.'.html');
    }
}