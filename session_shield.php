<?php

/**
 * 세션 쉴드 for 그누보드
 * 
 * XSS 공격, 세션 고정, 일부 상황에서의 세션 탈취를 방지하는 플러그인
 * 그누보드4/그누보드5 common.php의 "자동로그인" 부분 직전에 인클루드하여 사용
 * 자세한 설명은 XE용 애드온 참고: https://github.com/kijin/xe-session-shield
 * 
 * Copyright (c) 2015 Kijin Sung <kijin@kijinsung.com>
 * License: LGPL v2.1 <http://www.gnu.org/licenses/lgpl-2.1.html>
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
    const EXTRA_LIFETIME = 14400;
    const REFRESH_TIMEOUT = 600;
    const GRACE_PERIOD = 60;
    
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
        if ($_SERVER['REQUEST_METHOD'] !== 'GET' && $this->isFlash())
        {
            return false;
        }
        if (headers_sent())
        {
            return false;
        }
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
     * Check if the current request uses AJAX.
     * 
     * @return bool
     */
    public function isAjax()
    {
        return (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest');
    }
    
    /**
     * Check if the current request uses Flash.
     * 
     * @return bool
     */
    public function isFlash()
    {
        return (isset($_SERVER['HTTP_USER_AGENT']) && preg_match('/shockwave\s?flash/i', $_SERVER['HTTP_USER_AGENT']));
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
        if (!$this->isSessionActive()) return true;
        if (!$this->isShieldEnabled()) return true;
        
        if (!isset($_SESSION[self::ARRAY_KEY]['login']))
        {
            $_SESSION[self::ARRAY_KEY] = array(
                'init' => self::INIT_LEVEL_NONE,
                'login' => $this->getMemberID(),
                'cookie' => array(
                    'value' => $this->getRandomString(),
                    'previous' => null,
                    'last_refresh' => time(),
                    'need_refresh' => false,
                ),
                'cookie_ssl' => array(
                    'value' => null,
                    'previous' => null,
                    'last_refresh' => null,
                    'need_refresh' => false,
                ),
            );
            if ($this->isSecureRequest())
            {
                $_SESSION[self::ARRAY_KEY]['cookie_ssl'] = array(
                    'value' => $this->getRandomString(),
                    'previous' => null,
                    'last_refresh' => time(),
                    'need_refresh' => false,
                );
            }
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
        $cookie = isset($_COOKIE[self::COOKIE_NAME]) ? $_COOKIE[self::COOKIE_NAME] : 'none';
        $cookie_ssl = isset($_COOKIE[self::COOKIE_NAME_SSL]) ? $_COOKIE[self::COOKIE_NAME_SSL] : 'none';
        $resend_cookies = false;
        
        if ($_SESSION[self::ARRAY_KEY]['init'] == self::INIT_LEVEL_NONE)
        {
            return true;
        }
        elseif ($cookie === $_SESSION[self::ARRAY_KEY]['cookie']['value'])
        {
            // pass
        }
        elseif ($cookie === $_SESSION[self::ARRAY_KEY]['cookie']['previous'] &&
            $_SESSION[self::ARRAY_KEY]['cookie']['last_refresh'] > time() - self::GRACE_PERIOD)
        {
            $resend_cookies = true;
        }
        else
        {
            $this->destroySession();
            return false;
        }
        
        if ($this->isSecureRequest())
        {
            if ($_SESSION[self::ARRAY_KEY]['init'] < self::INIT_LEVEL_SSL)
            {
                $this->refreshSession();
                return true;
            }
            elseif ($cookie_ssl === $_SESSION[self::ARRAY_KEY]['cookie_ssl']['value'])
            {
                // pass
            }
            elseif ($cookie_ssl === $_SESSION[self::ARRAY_KEY]['cookie_ssl']['previous'] &&
                $_SESSION[self::ARRAY_KEY]['cookie_ssl']['last_refresh'] > time() - self::GRACE_PERIOD)
            {
                $resend_cookies = true;
            }
            else
            {
                $this->destroySession();
                return false;
            }
        }
        
        if ($resend_cookies)
        {
            return $this->setShieldCookies();
        }
        else
        {
            return true;
        }
    }
    
    /**
     * Check the refresh timeout.
     * 
     * @return bool
     */
    public function checkTimeout()
    {
        if (
            ($this->getMemberID() !== $_SESSION[self::ARRAY_KEY]['login']) ||
            ($_SESSION[self::ARRAY_KEY]['cookie']['need_refresh']) ||
            ($_SESSION[self::ARRAY_KEY]['cookie_ssl']['need_refresh'] && $this->isSecureRequest()) ||
            (self::REFRESH_TIMEOUT > 0 && $_SESSION[self::ARRAY_KEY]['cookie']['last_refresh'] < time() - self::REFRESH_TIMEOUT) ||
            (self::REFRESH_TIMEOUT > 0 && $_SESSION[self::ARRAY_KEY]['cookie_ssl']['last_refresh'] < time() - self::REFRESH_TIMEOUT && $this->isSecureRequest()))
        {
            $this->refreshSession();
        }
        return true;
    }
    
    /**
     * Set cookies related to Session Shield.
     * 
     * @return bool
     */
    public function setShieldCookies()
    {
        $params = session_get_cookie_params();
        $expiry = $params['lifetime'] > 0 ? (time() + $params['lifetime'] + self::EXTRA_LIFETIME) : 0;
        if ($_SESSION[self::ARRAY_KEY]['cookie']['value'] !== null)
        {
            $cookie_status = @setcookie(self::COOKIE_NAME, $_SESSION[self::ARRAY_KEY]['cookie']['value'],
                $expiry, $params['path'], $params['domain'], false, true);
            if ($cookie_status)
            {
                $_SESSION[self::ARRAY_KEY]['init'] = max($_SESSION[self::ARRAY_KEY]['init'], self::INIT_LEVEL_BASIC);
            }
            else
            {
                return false;
            }
        }
        
        if ($_SESSION[self::ARRAY_KEY]['cookie_ssl']['value'] !== null && $this->isSecureRequest())
        {
            $cookie_status = @setcookie(self::COOKIE_NAME_SSL, $_SESSION[self::ARRAY_KEY]['cookie_ssl']['value'],
                $expiry, $params['path'], $params['domain'], true, true);
            if ($cookie_status)
            {
                $_SESSION[self::ARRAY_KEY]['init'] = max($_SESSION[self::ARRAY_KEY]['init'], self::INIT_LEVEL_SSL);
            }
            else
            {
                return false;
            }
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
        if ($_SERVER['REQUEST_METHOD'] !== 'GET' || $this->isAjax() || $this->isFlash())
        {
            $_SESSION[self::ARRAY_KEY]['cookie']['need_refresh'] = true;
            if ($this->isSecureRequest())
            {
                $_SESSION[self::ARRAY_KEY]['cookie_ssl']['need_refresh'] = true;
            }
            return false;
        }
        else
        {
            $precomputed_random1 = $this->getRandomString();
            $precomputed_random2 = $this->isSecureRequest() ? $this->getRandomString() : null;
            $previous_session = $_SESSION[self::ARRAY_KEY];
            if (headers_sent())
            {
                return false;
            }
            
            $previous_value = $_SESSION[self::ARRAY_KEY]['cookie']['value'];
            session_write_close(); $_SESSION = array(); session_start();
            if ($_SESSION[self::ARRAY_KEY]['cookie']['value'] !== $previous_value)
            {
                return false;
            }
            
            $_SESSION[self::ARRAY_KEY]['cookie']['previous'] = $_SESSION[self::ARRAY_KEY]['cookie']['value'];
            $_SESSION[self::ARRAY_KEY]['cookie']['value'] = $precomputed_random1;
            $_SESSION[self::ARRAY_KEY]['cookie']['last_refresh'] = time();
            $_SESSION[self::ARRAY_KEY]['cookie']['need_refresh'] = false;
            if ($this->isSecureRequest())
            {
                $_SESSION[self::ARRAY_KEY]['cookie_ssl']['previous'] = $_SESSION[self::ARRAY_KEY]['cookie_ssl']['value'];
                $_SESSION[self::ARRAY_KEY]['cookie_ssl']['value'] = $precomputed_random2;
                $_SESSION[self::ARRAY_KEY]['cookie_ssl']['last_refresh'] = time();
                $_SESSION[self::ARRAY_KEY]['cookie_ssl']['need_refresh'] = false;
            }
            $_SESSION[self::ARRAY_KEY]['login'] = $this->getMemberID();
            
            $previous_value = $_SESSION[self::ARRAY_KEY]['cookie']['value'];
            session_write_close(); $_SESSION = array(); session_start();
            if ($_SESSION[self::ARRAY_KEY]['cookie']['value'] !== $previous_value)
            {
                return false;
            }
            
            $cookie_status = $this->setShieldCookies();
            if (!$cookie_status)
            {
                $_SESSION[self::ARRAY_KEY] = $previous_session;
                session_write_close();
                session_start();
            }
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

$shield = new Session_Shield();
$shield->initialize();
