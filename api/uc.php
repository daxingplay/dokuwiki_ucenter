<?php
/**
 * uc api for dokuwiki
 * @author dorange<daxingplay@gmail.com>
 */

error_reporting(0);

define('UC_CLIENT_VERSION', '1.6.0');
define('UC_CLIENT_RELEASE', '20110501');

define('API_DELETEUSER', 0);        //note 用户删除 API 接口开关
define('API_RENAMEUSER', 0);        //note 用户改名 API 接口开关
define('API_GETTAG', 0);        //note 获取标签 API 接口开关
define('API_SYNLOGIN', 1);      //note 同步登录 API 接口开关
define('API_SYNLOGOUT', 1);     //note 同步登出 API 接口开关
define('API_UPDATEPW', 0);      //note 更改用户密码 开关
define('API_UPDATEBADWORDS', 0);    //note 更新关键字列表 开关
define('API_UPDATEHOSTS', 1);       //note 更新域名解析缓存 开关
define('API_UPDATEAPPS', 1);        //note 更新应用列表 开关
define('API_UPDATECLIENT', 1);      //note 更新客户端缓存 开关
define('API_UPDATECREDIT', 0);      //note 更新用户积分 开关
define('API_GETCREDITSETTINGS', 0); //note 向 UCenter 提供积分设置 开关
define('API_GETCREDIT', 0);     //note 获取用户的某项积分 开关
define('API_UPDATECREDITSETTINGS', 0);  //note 更新应用积分设置 开关
define('API_ADDFEED', 0);
define('API_RETURN_SUCCEED', '1');
define('API_RETURN_FAILED', '-1');
define('API_RETURN_FORBIDDEN', '-2');

define('IN_DOKU', true);
define('IN_API', true);
define('CURSCRIPT', 'api');

if(!defined('IN_UC')) {
    define('DOKU_ROOT', dirname(dirname(__FILE__)).'/');
    require_once DOKU_ROOT.'./conf/uc.conf.php';

    $get = $post = array();

    $code = @$_GET['code'];
    parse_str(authcode($code, 'DECODE', UC_KEY), $get);
    
    $timestamp = time();
    if($timestamp - $get['time'] > 3600) {
        exit('Authracation has expiried');
    }
    if(empty($get)) {
        exit('Invalid Request');
    }

    include_once DOKU_ROOT.'./uc_client/lib/xml.class.php';
    $post = xml_unserialize(file_get_contents('php://input'));

    if(in_array($get['action'], array('test', 'deleteuser', 'renameuser', 'gettag', 'synlogin', 'synlogout', 'updatepw', 'updatebadwords', 'updatehosts', 'updateapps', 'updateclient', 'updatecredit', 'getcredit', 'getcreditsettings', 'updatecreditsettings', 'addfeed'))) {
        $uc_note = new uc_note();
        echo $uc_note->$get['action']($get, $post);
        exit();
    } else {
        exit(API_RETURN_FAILED);
    }
} else {
    exit('Access denied.');
}

class uc_note {

    var $dbconfig = '';
    var $db = '';
    var $tablepre = '';
    var $appdir = '';

    function _serialize($arr, $htmlon = 0) {
        if(!function_exists('xml_serialize')) {
            include_once DOKU_ROOT.'./uc_client/lib/xml.class.php';
        }
        return xml_serialize($arr, $htmlon);
    }

    function uc_note() {

    }

    function test($get, $post) {
        return API_RETURN_SUCCEED;
    }

    function deleteuser($get, $post) {
        // global $_G;
        if(!API_DELETEUSER) {
            return API_RETURN_FORBIDDEN;
        }

        return API_RETURN_SUCCEED;
    }

    function renameuser($get, $post) {
        // global $_G;

        if(!API_RENAMEUSER) {
            return API_RETURN_FORBIDDEN;
        }

        return API_RETURN_SUCCEED;
    }

    function gettag($get, $post) {
        // global $_G;
        if(!API_GETTAG) {
            return API_RETURN_FORBIDDEN;
        }
        return $this->_serialize(array($get['id'], array()), 1);
    }

    function synlogin($get, $post) {
        // global $_G; 
        global $conf;

        if(!API_SYNLOGIN) {
            return API_RETURN_FORBIDDEN;
        }

        header('P3P: CP="CURa ADMa DEVa PSAo PSDo OUR BUS UNI PUR INT DEM STA PRE COM NAV OTC NOI DSP COR"');
        
        // FIXME
        $cookietime = 31536000;
        $uid = intval($get['uid']);
        $username = $get['username'];
        $password_e = $get['password'];
        $time = $get['time'];
        // $member = uc_get_user($uid, 1);
        if($username) {
            // uc_setcookie($conf['auth']['uc']['cookie'], authcode("$member[password]\t$member[uid]", 'ENCODE'), $cookietime);
            uc_setcookie($conf['auth']['uc']['cookie'], authcode("$uid\t$password_e\t$username", 'ENCODE'), $cookietime);
        }
    }

    function synlogout($get, $post) {
        global $_G, $conf;

        if(!API_SYNLOGOUT) {
            return API_RETURN_FORBIDDEN;
        }

        header('P3P: CP="CURa ADMa DEVa PSAo PSDo OUR BUS UNI PUR INT DEM STA PRE COM NAV OTC NOI DSP COR"');

        uc_setcookie($conf['auth']['uc']['cookie'], '', -31536000);
    }

    function updatepw($get, $post) {
        global $_G;

        if(!API_UPDATEPW) {
            return API_RETURN_FORBIDDEN;
        }

        return API_RETURN_SUCCEED;
    }

    function updatebadwords($get, $post) {
        global $_G;

        if(!API_UPDATEBADWORDS) {
            return API_RETURN_FORBIDDEN;
        }

        return API_RETURN_SUCCEED;
    }

    function updatehosts($get, $post) {
        global $_G;

        if(!API_UPDATEHOSTS) {
            return API_RETURN_FORBIDDEN;
        }

        $cachefile = DOKU_ROOT.'./uc_client/data/cache/hosts.php';
        $fp = fopen($cachefile, 'w');
        $s = "<?php\r\n";
        $s .= '$_CACHE[\'hosts\'] = '.var_export($post, TRUE).";\r\n";
        fwrite($fp, $s);
        fclose($fp);

        return API_RETURN_SUCCEED;
    }

    function updateapps($get, $post) {
        global $_G;

        if(!API_UPDATEAPPS) {
            return API_RETURN_FORBIDDEN;
        }

        $UC_API = '';
        if($post['UC_API']) {
            $UC_API = $post['UC_API'];
            unset($post['UC_API']);
        }

        $cachefile = DOKU_ROOT.'./uc_client/data/cache/apps.php';
        $fp = fopen($cachefile, 'w');
        $s = "<?php\r\n";
        $s .= '$_CACHE[\'apps\'] = '.var_export($post, TRUE).";\r\n";
        fwrite($fp, $s);
        fclose($fp);

        if($UC_API && is_writeable(DOKU_ROOT.'./conf/uc.conf.php')) {
            if(preg_match('/^https?:\/\//is', $UC_API)) {
                $configfile = trim(file_get_contents(DOKU_ROOT.'./conf/uc.conf.php'));
                $configfile = substr($configfile, -2) == '?>' ? substr($configfile, 0, -2) : $configfile;
                $configfile = preg_replace("/define\('UC_API',\s*'.*?'\);/i", "define('UC_API', '".addslashes($UC_API)."');", $configfile);
                if($fp = @fopen(DOKU_ROOT.'./config/conf/uc.conf.php', 'w')) {
                    @fwrite($fp, trim($configfile));
                    @fclose($fp);
                }
            }
        }
        return API_RETURN_SUCCEED;
    }

    function updateclient($get, $post) {
        global $_G;

        if(!API_UPDATECLIENT) {
            return API_RETURN_FORBIDDEN;
        }

        $cachefile = DOKU_ROOT.'./uc_client/data/cache/settings.php';
        $fp = fopen($cachefile, 'w');
        $s = "<?php\r\n";
        $s .= '$_CACHE[\'settings\'] = '.var_export($post, TRUE).";\r\n";
        fwrite($fp, $s);
        fclose($fp);

        return API_RETURN_SUCCEED;
    }

    function updatecredit($get, $post) {
        global $_G;

        if(!API_UPDATECREDIT) {
            return API_RETURN_FORBIDDEN;
        }

        return API_RETURN_SUCCEED;
    }

    // function getcredit($get, $post) {
        // global $_G;
// 
        // if(!API_GETCREDIT) {
            // return API_RETURN_FORBIDDEN;
        // }
        // $uid = intval($get['uid']);
        // $credit = intval($get['credit']);
        // $_G['uid'] = $uid;
        // return getuserprofile('extcredits'.$credit);
    // }

    // function getcreditsettings($get, $post) {
        // global $_G;
// 
        // if(!API_GETCREDITSETTINGS) {
            // return API_RETURN_FORBIDDEN;
        // }
// 
        // $credits = array();
        // foreach($_G['setting']['extcredits'] as $id => $extcredits) {
            // $credits[$id] = array(strip_tags($extcredits['title']), $extcredits['unit']);
        // }
// 
        // return $this->_serialize($credits);
    // }

    function updatecreditsettings($get, $post) {
        global $_G;

        if(!API_UPDATECREDITSETTINGS) {
            return API_RETURN_FORBIDDEN;
        }
        return API_RETURN_SUCCEED;
    }

    function addfeed($get, $post) {
        global $_G;

        if(!API_ADDFEED) {
            return API_RETURN_FORBIDDEN;
        }
        return API_RETURN_SUCCEED;
    }
}

function authcode($string, $operation = 'DECODE', $key = '', $expiry = 0) {

    $ckey_length = 4;

    $key = md5($key ? $key : UC_KEY);
    $keya = md5(substr($key, 0, 16));
    $keyb = md5(substr($key, 16, 16));
    $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length): substr(md5(microtime()), -$ckey_length)) : '';

    $cryptkey = $keya.md5($keya.$keyc);
    $key_length = strlen($cryptkey);

    $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0).substr(md5($string.$keyb), 0, 16).$string;
    $string_length = strlen($string);

    $result = '';
    $box = range(0, 255);

    $rndkey = array();
    for($i = 0; $i <= 255; $i++) {
        $rndkey[$i] = ord($cryptkey[$i % $key_length]);
    }

    for($j = $i = 0; $i < 256; $i++) {
        $j = ($j + $box[$i] + $rndkey[$i]) % 256;
        $tmp = $box[$i];
        $box[$i] = $box[$j];
        $box[$j] = $tmp;
    }

    for($a = $j = $i = 0; $i < $string_length; $i++) {
        $a = ($a + 1) % 256;
        $j = ($j + $box[$a]) % 256;
        $tmp = $box[$a];
        $box[$a] = $box[$j];
        $box[$j] = $tmp;
        $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
    }

    if($operation == 'DECODE') {
        if((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26).$keyb), 0, 16)) {
            return substr($result, 26);
        } else {
            return '';
        }
    } else {
        return $keyc.str_replace('=', '', base64_encode($result));
    }

}

function uc_serialize($arr, $htmlon = 0) {
    include_once UC_CLIENT_ROOT.'./lib/xml.class.php';
    return xml_serialize($arr, $htmlon);
}

function uc_unserialize($s) {
    include_once UC_CLIENT_ROOT.'./lib/xml.class.php';
    return xml_unserialize($s);
}

function uc_setcookie($var, $value = '', $life = 0, $httponly = false) {

    global $conf, $timestamp;

    $config = $conf['auth']['uc'];
    
    $_COOKIE[$var] = $value;

    if($value == '' || $life < 0) {
        $value = '';
        $life = -1;
    }

    $life = $life > 0 ? $timestamp + $life : ($life < 0 ? $timestamp - 31536000 : 0);
    $path = $httponly && PHP_VERSION < '5.2.0' ? $config['cookiepath'].'; HttpOnly' : $config['cookiepath'];

    $secure = $_SERVER['SERVER_PORT'] == 443 ? 1 : 0;
    if(PHP_VERSION < '5.2.0') {
        setcookie($var, $value, $life, $path, $config['cookiedomain'], $secure);
    } else {
        setcookie($var, $value, $life, $path, $config['cookiedomain'], $secure, $httponly);
    }
}
?>