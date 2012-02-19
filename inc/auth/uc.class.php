<?php
/**
 * ucenter auth backend.
 * 
 * @license  GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author   橘子<daxingplay@gmail.com>
 * @version  1.0 beta
 */

define('DOKU_AUTH', dirname(__FILE__));
require_once(DOKU_INC.'/conf/uc.conf.php');
require_once(DOKU_INC.'/uc_client/client.php');

class auth_uc extends auth_basic {
    
    var $cnf;
    var $users = NULL;

    function auth_uc(){
        global $conf;
        $this->cnf = $conf['auth']['uc'];
        
        if(method_exists($this, 'auth_basic')){
            parent::auth_basic();
        }
        
        if(!function_exists('uc_authcode')){
            if($this->cnf['debug']){
                msg('Cannot find UC client API.', -1, __LINE__, __FILE__);
            }
            $this->success = false;
            return;
        }
        
        if(!isset($this->cnf['charset'])){
            $this->cnf['charset'] = 'utf8';
        }
        
        if(!isset($this->cnf['sync'])){
            $this->cnf['sync'] = true;
        }
        
        if(!isset($this->cnf['cookie'])){
            $this->cnf['cookie'] = 'dokuwiki_uc_auth';
        }
        
        // must forward clear pass.
        $this->cnf['forwardClearPass'] = 1;
        
        // TODO check uc config
        if(0){
            if($this->cnf['debug']){
                msg('UC auth config error.', -1, __LINE__, __FILE__);
            }
            $this->success = false;
            return;
        }
        
        /*
        $cando = array (
            'addUser'     => false, // can Users be created?
            'delUser'     => false, // can Users be deleted?
            'modLogin'    => false, // can login names be changed?
            'modPass'     => false, // can passwords be changed?
            'modName'     => false, // can real names be changed?
            'modMail'     => false, // can emails be changed?
            'modGroups'   => false, // can groups be changed?
            'getUsers'    => false, // can a (filtered) list of users be retrieved?
            'getUserCount'=> false, // can the number of users be retrieved?
            'getGroups'   => false, // can a list of available groups be retrieved?
            'external'    => false, // does the module do external auth checking?
            'logoff'      => false, // has the module some special logoff method?
        );
        */
        $this->cando['addUser'] = true;
        $this->cando['delUser'] = true;
        $this->cando['modLogin'] = false;
        $this->cando['modPass'] = false;
        $this->cando['modName'] = true;
        $this->cando['modMail'] = true;
        $this->cando['modGroups'] = true;
        $this->cando['getUsers'] = true;
        $this->cando['getUserCount'] = false;
        $this->cando['getGroups'] = true;
        $this->cando['external'] = $this->cnf['sync'];
        $this->cando['logoff'] = true;
        
    }

    function logOff(){
        // if(isset($_SESSION[DOKU_COOKIE]['auth']['uid'])){
            // unset($_SESSION[DOKU_COOKIE]['auth']['uid']);
        // }
        // if(isset($_SESSION[DOKU_COOKIE]['auth']['buid'])){
            // unset($_SESSION[DOKU_COOKIE]['auth']['buid']);
        // }
        // if(isset($_SESSION[DOKU_COOKIE]['auth']['time'])){
            // unset($_SESSION[DOKU_COOKIE]['auth']['time']);
        // }
        // @session_start();
        // session_destroy();
        $this->_uc_setcookie($this->cnf['cookie'], '', -1);
        // ob_end_clean();
        $synlogout = uc_user_synlogout();
        msg($synlogout, 0);
        // echo $synlogout;
    }

    /**
     * Checks if the given user exists and the given plaintext password
     * is correct. Furtheron it might be checked wether the user is
     * member of the right group
     *
     * Depending on which SQL string is defined in the config, password
     * checking is done here (getpass) or by the database (passcheck)
     *
     * @param  $user  user who would like access
     * @param  $pass  user's clear text password to check
     * @return bool
     */
    function checkPass($user, $pass){
        list($uid, $username, $password, $email) = $this->_uc_user_login($user, $pass);
        if($uid > 0){
            return true;
        }else{
            return false;
        }
    }
    
    /**
     * [public function]
     *
     * Returns info about the given user needs to contain
     * at least these fields:
     *   name  string  full name of the user
     *   mail  string  email addres of the user
     *   grps  array   list of groups the user is in
     *
     * @param $user   user's nick to get data for
     *
     * @author  Andreas Gohr <andi@splitbrain.org>
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     */
    function getUserData($user, $isuid = 0){
        $user_info = false;
        $isuid = intval($isuid);
        if($data = $this->_uc_get_user($user, $isuid)){
            list($uid, $username, $email) = $data;
            $user_info = array(
                'name' => $username,
                'mail' => $email,
                'grps' => array('user'),
                'uid' => $uid
            );
        }
        return $user_info;
    }
    
    /**
     * [public function]
     *
     * Create a new User. Returns false if the user already exists,
     * null when an error occurred and true if everything went well.
     *
     * The new user will be added to the default group by this
     * function if grps are not specified (default behaviour).
     *
     * @param $user  nick of the user
     * @param $pwd   clear text password
     * @param $name  full name of the user
     * @param $mail  email address
     * @param $grps  array of groups the user should become member of
     */
    function createUser($user, $pwd, $name, $mail, $grps=null){
        $uid = $this->_uc_user_register($user, $pwd, $mail);
        $msg = '';
        if($uid > 0){
            return true;
        }else{
            switch($uid){
                case -1:
                    $msg = '用户名不合法';
                    break;
                case -2:
                    $msg = '包含不允许注册的词语';
                    break;
                case -3:
                    $msg = '用户名已经存在';
                    break;
                case -4:
                    $msg = 'Email 格式有误';
                    break;
                case -5:
                    $msg = 'Email 不允许注册';
                    break;
                case -6:
                    $msg = '该 Email 已经被注册';
                    break;
            }
        }
        msg($msg, -1);
        return null;
    }
    
    /**
     * Modify user data [public function]
     *
     * An existing user dataset will be modified. Changes are given in an array.
     *
     * The dataset update will be rejected if the user name should be changed
     * to an already existing one.
     *
     * The password must be provides unencrypted. Pasword cryption is done
     * automatically by ucenter.
     *
     * If one or more groups could't be updated, an error would be set. In
     * this case the dataset might already be changed and we can't rollback
     * the changes. Transactions would be really usefull here.
     *
     * modifyUser() may be called without SQL statements defined that are
     * needed to change group membership (for example if only the user profile
     * should be modified). In this case we asure that we don't touch groups
     * even $changes['grps'] is set by mistake.
     *
     * @param   $user     nick of the user to be changed
     * @param   $changes  array of field/value pairs to be changed (password
     *                    will be clear text)
     * @return  bool      true on success, false on error
     */
    function modifyUser($user, $changes){
        if(!is_array($changes) || !count($changes)){
            return true;
        }
        $ucresult = $this->_uc_user_edit($user, $_POST['oldpass'], $changes['pass'] ? $changes['pass'] : '', $changes['mail'] ? $changes['mail'] : '');
        $msg = '';
        switch($ucresult){
            case 1:
            case 0:
            case -7:
                return true;
                break;
            case -1:
                $msg = '密码不正确！';
                break;
            case -4:
                $msg = 'Email 格式错误！';
                break;
            case -5:
                $msg = 'Email 不允许注册！';
                break;
            case -6:
                $msg = 'Email 已经被注册！';
                break;   
            case -8:
                $msg = '该用户受保护无权限更改！';
                break; 
        }
        msg($msg, -1);
        return false;
    }
    
    /**
     * [public function]
     *
     * Remove one or more users from the list of registered users
     *
     * @param   array  $users   array of users to be deleted
     * @return  int             the number of users deleted
     *
     * @author  Christopher Smith <chris@jalakai.co.uk>
     * @author  Matthias Grimm <matthiasgrimm@users.sourceforge.net>
     */
    function deleteUsers($users){
        $count = 0;
        if(is_array($users) && count($users)){
            foreach($users as $user){
                $uid = $this->get_uid($user);
                if($uid && uc_user_delete($uid)){
                    $count++;
                }
            }
        }
        return $count;
    }
    
    /**
     * TODO ucenter api does not support filter
     * [public function]
     *
     * Counts users which meet certain $filter criteria.
     *
     * @param  array  $filter  filter criteria in item/pattern pairs
     * @return count of found users.
     */
    function getUserCount($filter=array()){
        $count = 0;
        $condition = '';
        if($this->users !== NULL){
            $count = count($this->users);
        }else{
            if(!empty($filter)){
                $condition = $this->_construct_filter($filter);
            }
            $count = uc_user_totalnum($condition);
        }
        return $count;
    }
    
    /**
     * FIXME ucenter api does not support filter, I added by myself
     * FIXME the user group
     * Bulk retrieval of user data. [public function]
     *
     * @param   first     index of first user to be returned
     * @param   limit     max number of users to be returned
     * @param   filter    array of field/pattern pairs
     * @return  array of userinfo (refer getUserData for internal userinfo details)
     */
    function retrieveUsers($first = 0, $limit = 10, $filter = array()){
        $condition = '';
        $return = array();
        if(count($filter)){
            $condition = $this->_construct_filter($filter);
            $return = $this->_filter_uc_user_data(uc_get_userlist($first, $limit, $condition));
        }else{
            if($this->users === NULL){
                $this->users = $this->_filter_uc_user_data(uc_get_userlist($first, $limit));
            }
            $return = $this->users;
        }
        return $return;
    }
    
   /**
    * Do all authentication [ OPTIONAL ]
    *
    * Set $this->cando['external'] = true when implemented
    *
    * If this function is implemented it will be used to
    * authenticate a user - all other DokuWiki internals
    * will not be used for authenticating, thus
    * implementing the checkPass() function is not needed
    * anymore.
    *
    * The function can be used to authenticate against third
    * party cookies or Apache auth mechanisms and replaces
    * the auth_login() function
    *
    * The function will be called with or without a set
    * username. If the Username is given it was called
    * from the login form and the given credentials might
    * need to be checked. If no username was given it
    * the function needs to check if the user is logged in
    * by other means (cookie, environment).
    *
    * The function needs to set some globals needed by
    * DokuWiki like auth_login() does.
    *
    * @see auth_login()
    *
    * @param   string  $user    Username
    * @param   string  $pass    Cleartext Password
    * @param   bool    $sticky  Cookie should not expire
    * @return  bool             true on successful auth
    */
    function trustExternal($user, $pass, $sticky = false){
        global $USERINFO;
        global $conf;
        global $lang;
        // global $auth;
        global $ACT;
        $sticky ? $sticky = true : $sticky = false; //sanity check
    
        // if (!$auth) return false;
        $uid = '';
        $username = '';
        $password = '';
        $email = '';
        $checked = false;
        
        if(!empty($user)){
            list($uid, $username, $password, $email) = $this->_uc_user_login($user, $pass);
            setcookie($this->cnf['cookie'], '', -86400);
            if($uid > 0){
                $_SERVER['REMOTE_USER'] = $username;
                $user_info = $this->_uc_get_user_full($uid, 1);
                $this->_uc_setcookie($this->cnf['cookie'], uc_authcode($uid."\t".$user_info['password']."\t".$this->_convert_charset($username), 'ENCODE'));
                $synlogin = uc_user_synlogin($uid);
                // echo uc_user_synlogin($uid);
                // echo does not send the output correctly, but function msg() can store the messages in session and output them even the page refreshes.
                msg($synlogin, 0);
                $checked = true;
            }else{
                if(!$silent){
                    $msg = '';
                    switch($login_uid){
                        case -1:
                            $msg = '用户名不存在或者被删除';
                            break;
                        case -2:
                        default:
                            $msg = $lang['badlogin'];
                            break;
                    }
                    msg($msg, -1);
                }
                // auth_logoff();
                // return false;
                $checked = false;
            }
        }else{
            $cookie = $_COOKIE[$this->cnf['cookie']];
            if(!empty($cookie)){
                // use password check instead of username check.
                list($uid, $password, $username) = explode("\t", uc_authcode($cookie, 'DECODE'));
                $username = $this->_convert_charset($username, 0);
                if($password && $uid && $username){
                    // get session info
                    $session = $_SESSION[DOKU_COOKIE]['auth'];
                    if(isset($session) && $session['user'] == $username && $session['pass'] == $password && $session['buid'] == auth_browseruid()){
                        $user_info = $session['info'];
                        $checked = true;
                    }else{
                        $user_info = $this->_uc_get_user_full($uid, 1);
                        if($uid == $user_info['uid'] && $password == $user_info['password']){
                            // he has logged in from other uc apps
                            $checked = true;
                        }
                    }
                    
                }
            }
        }

        if($checked == true){
            $_SERVER['REMOTE_USER'] = $username;
            $USERINFO = $user_info; //FIXME move all references to session
            // $session['info'] = $user_info;
            // set session
            // $_SESSION[DOKU_COOKIE]['auth']['uid'] = $uid;
            $_SESSION[DOKU_COOKIE]['auth']['user'] = $username;
            $_SESSION[DOKU_COOKIE]['auth']['pass'] = $password;
            $_SESSION[DOKU_COOKIE]['auth']['buid'] = auth_browseruid();
            $_SESSION[DOKU_COOKIE]['auth']['info'] = $user_info;
            $_SESSION[DOKU_COOKIE]['auth']['time'] = time();
            // return true;
        }else{
            // auth_logoff();
            // return false;
        }
        return $checked;
        
        /*
        if($ACT != 'logout'){
            if(!empty($user)){
                // uc login
                $login_uid = $login_username = $login_password = $login_email = '';
                list($login_uid, $login_username, $login_password, $login_email) = $this->_uc_user_login($user, $pass);
                setcookie($this->cnf['cookie'], '', -86400);
                if ($login_uid > 0){
                    // make logininfo globally available
                    $_SERVER['REMOTE_USER'] = $login_username;
                    $_SESSION[DOKU_COOKIE]['auth']['uid'] = $login_uid;
                    auth_setCookie($login_username,PMA_blowfish_encrypt($login_password, auth_cookiesalt()), $sticky);
                    // setcookie($this->cnf['cookie'], uc_authcode($login_uid."\t".$this->_convert_charset($login_username), 'ENCODE'));
                    $this->_uc_setcookie($this->cnf['cookie'], uc_authcode($login_uid."\t".$this->_convert_charset($login_username), 'ENCODE'), $sticky);
                    // uc sync login
                    echo uc_user_synlogin($login_uid);
                    return true;
                }else{
                    //invalid credentials - log off
                    if(!$silent){
                        $msg = '';
                        switch($login_uid){
                            case -1:
                                $msg = '用户名不存在或者被删除';
                                break;
                            case -2:
                            default:
                                $msg = $lang['badlogin'];
                                break;
                        }
                        msg($msg, -1);
                    }
                    auth_logoff();
                    return false;
                }
            }else{
                // get session info
                $session = $_SESSION[DOKU_COOKIE]['auth'];
                // TODO read ucenter cookie information
                $uc_cookie = $_COOKIE[$this->cnf['cookie']];
                $uc_username = '';
                $uc_uid = 0;
                $checked = false;
                if(!empty($uc_cookie)){
                    list($uc_uid, $uc_username) = explode("\t", uc_authcode($uc_cookie, 'DECODE'));
                    $uc_username = $this->_convert_charset($uc_username, 0);
                    if($uc_username && $uc_uid){
                        if(isset($session) && $session['user'] == $uc_username && $session['buid'] == auth_browseruid()){
                            $checked = true;
                        }else{
                            $uc_info = $this->getUserData($uc_uid, 1);
                            if($uc_username == $uc_info['name']){
                                // he has logged in from other uc apps
                                $checked = true;
                                $session['info'] = $uc_info;
                                // set session
                                $_SESSION[DOKU_COOKIE]['auth']['uid'] = $uc_uid;
                                $_SESSION[DOKU_COOKIE]['auth']['user'] = $uc_username;
                                // $_SESSION[DOKU_COOKIE]['auth']['pass'] = '';
                                $_SESSION[DOKU_COOKIE]['auth']['buid'] = auth_browseruid();
                                $_SESSION[DOKU_COOKIE]['auth']['info'] = $uc_info;
                                $_SESSION[DOKU_COOKIE]['auth']['time'] = time();
                            }
                        }
                        if($checked == true){
                            $_SERVER['REMOTE_USER'] = $uc_username;
                            $USERINFO = $session['info']; //FIXME move all references to session
                            return true;
                        }
                    }
                }else{
                    // read doku cookie information
                    list($user,$sticky,$pass) = auth_getCookie();
                    if($user && $pass){
                        // we got a cookie - see if we can trust it
                        if(isset($session) &&
                                $auth->useSessionCache($user) &&
                                ($session['time'] >= time()-$conf['auth_security_timeout']) &&
                                ($session['user'] == $user) &&
                                ($session['pass'] == $pass) &&  //still crypted
                                ($session['buid'] == auth_browseruid()) ){
                            // he has session, cookie and browser right - let him in
                            $_SERVER['REMOTE_USER'] = $user;
                            $USERINFO = $session['info']; //FIXME move all references to session
                            return true;
                        }
                        // no we don't trust it yet - recheck pass but silent
                        $pass = PMA_blowfish_decrypt($pass,auth_cookiesalt());
                        return auth_login($user,$pass,$sticky,true);
                    }
                }
            }
        }
        //just to be sure
        auth_logoff(true);
        return false;
        */
    }
    
    /**
     * get user id frome ucenter
     * 
     * @param  string $username  the name of the user
     * @return int               the user id. 0 on error.
     */
    function get_uid($username){
        $uid = 0;
        if($data = $this->_uc_get_user($username)) {
            $uid = $data[0];
        }
        return $uid;
    }
    
    private function _filter_uc_user_data($user_data){
        $return = array();
        if(is_array($user_data)){
            foreach($user_data as $key=>$val){
                $return[] = array(
                    'user' => $val['username'],
                    'mail' => $val['email'],
                    'fullname' => $val['username']
                );
            }
        }
        return $return;
    }
    
    /**
     * convert doku filter to sql condition slot
     * @param  array $filter   the dokuwiki's filter
     * @return the sql statement
     */
    private function _construct_filter($filter){
        $sql = 'WHERE 1';
        $item_name = '';
        foreach($filter as $item => $info){
            switch($item){
                case 'user':
                    $item_name = 'username';
                    break;
                case 'mail':
                    $item_name = 'email';
                    break;
                default:
                    break;
            }
            if($item_name){
                $sql .= " AND `$item_name` LIKE '%$info%'";
            }
        }
        return $sql;
    }
    
    /**
     * convert charset
     * @param string $str  the string that to be converted.
     * @param bool   $out  1: doku convert to other char, 0: other char convert to doku
     */
    private function _convert_charset($str, $out = 1){
        if($this->cnf['charset'] != 'utf-8'){
            $str = $out ? iconv('utf-8', $this->cnf['charset'], $str) : iconv($this->cnf['charset'], 'utf-8', $str);
        }
        return $str;
    }
    
    private function _uc_user_login($username, $password){
        $return = uc_user_login($this->_convert_charset($username), $password);
        return array($return[0], $this->_convert_charset($return[1], 0), $return[2], $return[3], $return[4]);
    }
    
    private function _uc_get_user($username, $isuid = 0){
        $return = uc_get_user($this->_convert_charset($username), $isuid);
        return array($return[0], $this->_convert_charset($return[1], 0), $return[2]);
    }
    
    private function _uc_user_register($username, $password, $email){
        return uc_user_register($this->_convert_charset($username), $password, $email);
    }
    
    private function _uc_user_edit($username, $oldpw, $newpw, $email){
        return uc_user_edit($this->_convert_charset($username), $oldpw, $newpw, $email, 0);
    }
    
    private function _uc_setcookie($var, $value = '', $life = 0, $httponly = false) {

        $_COOKIE[$var] = $value;
        
        $timestamp = time();
    
        if($value == '' || $life < 0) {
            $value = '';
            $life = -1;
        }
    
        $life = $life > 0 ? $timestamp + $life : ($life < 0 ? $timestamp - 31536000 : 0);
        $path = $httponly && PHP_VERSION < '5.2.0' ? $this->cnf['cookiepath'].'; HttpOnly' : $this->cnf['cookiepath'];
    
        $secure = $_SERVER['SERVER_PORT'] == 443 ? 1 : 0;
        if(PHP_VERSION < '5.2.0') {
            setcookie($var, $value, $life, $path, $this->cnf['cookiedomain'], $secure);
        } else {
            setcookie($var, $value, $life, $path, $this->cnf['cookiedomain'], $secure, $httponly);
        }
    }
    
    private function _uc_get_user_full($username, $isuid = 0){
        global $uc_controls;
        if(empty($uc_controls['user'])){
            require_once(DOKU_INC.'/uc_client/lib/db.class.php');
            require_once(DOKU_INC.'/uc_client/model/base.php');
            require_once(DOKU_INC.'/uc_client/control/user.php');
            $uc_controls['user'] = new usercontrol();
        }
        $args = uc_addslashes(array('username' => $username, 'isuid' => $isuid), 1, TRUE);
        $uc_controls['user']->input = $args;
        $uc_controls['user']->init_input();
        $username = $uc_controls['user']->input('username');
        if(!$uc_controls['user']->input('isuid')) {
            $status = $_ENV['user']->get_user_by_username($username);
        } else {
            $status = $_ENV['user']->get_user_by_uid($username);
        }
        if($status) {
            // do not return salt.
            return array(
                'uid' => $status['uid'],
                'username' => $status['username'],
                'password' => $status['password'],
                'email' => $status['email'],
                'regip' => $status['regip'],
                'regdate' => $status['regdate'],
                'lastloginip' => $status['lastloginip'],
                'lastlogintime' => $status['lastlogintime']
            );
        } else {
            return 0;
        }
    }
}

?>