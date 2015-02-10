<?php

/**
 * 세션 쉴드 for 그누보드
 * 
 * XSS 공격, 세션 고정, 일부 상황에서의 세션 탈취를 방지하는 플러그인
 * 그누보드4/그누보드5 common.php의 "자동로그인" 부분 직전에 인클루드하여 사용
 * 자세한 설명은 XE용 애드온 참고: https://github.com/kijin/xe-session-shield
 * 
 * Copyright (c) 2015 Kijin Sung <kijin@kijinsung.com>
 */

class Session_Shield
{
    /**
     * Class constants
     */
    const ARRAY_KEY = 'ss_shield';
    const COOKIE_NAME = 'ss_shield1';
    const COOKIE_NAME_SSL = 'ss_shield2';
    const COOKIE_HASH_ALGO = 'sha1';
    const INIT_LEVEL_NONE = 0;
    const INIT_LEVEL_BASIC = 1;
    const INIT_LEVEL_SSL = 2;
    const REFRESH_TIMEOUT = 300;
    
    /**
     * Check if the session is active.
     * 
     * @return bool
     */
    public function isSessionActive()
    {
        if (function_exists('session_status'))
        {
            return (session_status() === PHP_SESSION_ACTIVE);
        }
        else
        {
            return (session_id() !== '');
        }
    }
    
    /**
     * Check if the session shield is usable in the current request.
     * 
     * @return bool
     */
    public function isShieldEnabled()
    {
        return true;
    }
    
    /**
     * Check if the current request uses SSL.
     * 
     * @return bool
     */
    public function isSecureRequest()
    {
        return (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    }
    
    /**
     * Check if the user's browser is known to forget session cookies.
     * 
     * @return bool
     */
    public function isStupidBrowser()
    {
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        return (strpos($ua, 'MSIE 8.0') !== false || strpos($ua, 'Trident/4.0') !== false);
    }
    
    /**
     * Get the username of the current user.
     * 
     * @return int
     */
    public function getMemberID()
    {
        return isset($_SESSION['ss_mb_id']) ? strval($_SESSION['ss_mb_id']) : '';
    }
    
    /**
     * Initialize session variables for Session Shield.
     * 
     * @return bool
     */
    public function initialize()
    {
        if (!$this->isSessionActive()) return false;
        if (!$this->isShieldEnabled()) return true;
        
        if (!isset($_SESSION[self::ARRAY_KEY]))
        {
            $_SESSION[self::ARRAY_KEY] = array(
                'init' => self::INIT_LEVEL_NONE,
                'cookie' => $this->getRandomString(),
                'cookie_ssl' => $this->isSecureRequest() ? $this->getRandomString() : '',
                'last_refresh' => time(),
                'need_refresh' => false,
                'member_id' => $this->getMemberID(),
            );
            $this->setShieldCookies();
            return true;
        }
        
        if (!$this->checkCookies()) return false;
        if (!$this->checkTimeout()) return false;
        return true;
    }
    
    /**
     * Check the cookies.
     * 
     * @return bool
     */
    public function checkCookies()
    {
        if ($_SESSION[self::ARRAY_KEY]['init'] == self::INIT_LEVEL_NONE) return false;
        
        $cookie = isset($_COOKIE[self::COOKIE_NAME]) ? $_COOKIE[self::COOKIE_NAME] : false;
        $cookie_ssl = isset($_COOKIE[self::COOKIE_NAME_SSL]) ? $_COOKIE[self::COOKIE_NAME_SSL] : false;
        
        if ($cookie === false || $cookie !== $_SESSION[self::ARRAY_KEY]['cookie'])
        {
            $this->destroySession();
            return false;
        }
        
        if ($this->isSecureRequest())
        {
            if ($_SESSION[self::ARRAY_KEY]['init'] < self::INIT_LEVEL_SSL)
            {
                $this->refreshSession();
            }
            elseif ($cookie_ssl === false || $cookie_ssl !== $_SESSION[self::ARRAY_KEY]['cookie_ssl'])
            {
                $this->destroySession();
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * Check the refresh timeout.
     * 
     * @return bool
     */
    public function checkTimeout()
    {
        if ($_SESSION[self::ARRAY_KEY]['need_refresh'] || $_SESSION[self::ARRAY_KEY]['last_refresh'] < time() - self::REFRESH_TIMEOUT)
        {
            $this->refreshSession();
            return true;
        }
        elseif ($this->getMemberID() !== $_SESSION[self::ARRAY_KEY]['member_id'])
        {
            $this->refreshSession();
            return true;
        }
        else
        {
            return true;
        }
    }
    
    /**
     * Set cookies related to Session Shield.
     * 
     * @return bool
     */
    public function setShieldCookies()
    {
        if (headers_sent()) return false;
        
        $params = session_get_cookie_params();
        if ($_SESSION[self::ARRAY_KEY]['cookie'] !== '')
        {
            setcookie(self::COOKIE_NAME, $_SESSION[self::ARRAY_KEY]['cookie'],
                $params['lifetime'], $params['path'], $params['domain'], false, true);
            $_SESSION[self::ARRAY_KEY]['init'] = max($_SESSION[self::ARRAY_KEY]['init'], self::INIT_LEVEL_BASIC);
        }
        if ($_SESSION[self::ARRAY_KEY]['cookie_ssl'] !== '' && $this->isSecureRequest())
        {
            setcookie(self::COOKIE_NAME_SSL, $_SESSION[self::ARRAY_KEY]['cookie_ssl'],
                $params['lifetime'], $params['path'], $params['domain'], true, true);
            $_SESSION[self::ARRAY_KEY]['init'] = max($_SESSION[self::ARRAY_KEY]['init'], self::INIT_LEVEL_SSL);
        }
        
        return true;
    }
    
    /**
     * Refresh the session and all Session Shoeld cookies.
     * 
     * @return bool
     */
    public function refreshSession()
    {
        if ($this->isStupidBrowser() && $_SERVER['REQUEST_METHOD'] !== 'GET')
        {
            $_SESSION[self::ARRAY_KEY]['need_refresh'] = true;
            return false;
        }
        else
        {
            $_SESSION[self::ARRAY_KEY]['cookie'] = $this->getRandomString();
            if ($this->isSecureRequest()) $_SESSION[self::ARRAY_KEY]['cookie_ssl'] = $this->getRandomString();
            $_SESSION[self::ARRAY_KEY]['last_refresh'] = time();
            $_SESSION[self::ARRAY_KEY]['need_refresh'] = false;
            $_SESSION[self::ARRAY_KEY]['member_id'] = $this->getMemberID();
            return $this->setShieldCookies();
        }
    }
    
    /**
     * Destroy the session and all Session Shield cookies.
     * 
     * @return bool
     */
    public function destroySession()
    {
        if (headers_sent()) return false;
        
        $_SESSION = array();
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 86400, $params['path'], $params['domain'], false, false);
        setcookie(self::COOKIE_NAME, '', time() - 86400, $params['path'], $params['domain'], false, false);
        setcookie(self::COOKIE_NAME_SSL, '', time() - 86400, $params['path'], $params['domain'], false, false);
        session_destroy();
        
        return true;
    }
    
    /**
     * Generate a 40-byte random string.
     * 
     * @return string
     */
    public function getRandomString()
    {
        if (class_exists('Password') && ($pw = new Password()) && method_exists($pw, 'createSecureSalt'))
        {
            return $pw->createSecureSalt(40, 'hex');
        }
        else
        {
            $is_windows = (defined('PHP_OS') && strtoupper(substr(PHP_OS, 0, 3)) === 'WIN');
            if (function_exists('openssl_random_pseudo_bytes') && (!$is_windows || version_compare(PHP_VERSION, '5.4', '>=')))
            {
                return hash(self::COOKIE_HASH_ALGO, openssl_random_pseudo_bytes(20));
            }
            elseif (function_exists('mcrypt_create_iv') && (!$is_windows || version_compare(PHP_VERSION, '5.3.7', '>=')))
            {
                return hash(self::COOKIE_HASH_ALGO, mcrypt_create_iv(20, MCRYPT_DEV_URANDOM));
            }
            else
            {
                $result = sprintf('%s %s %s', rand(), mt_rand(), microtime());
                for ($i = 0; $i < 100; $i++)
                {
                    $result = hash(self::COOKIE_HASH_ALGO, $result . mt_rand());
                }
                return $result;
            }
        }
    }
}

$shield = new Session_Shield();
$shield->initialize();
