<?php

use Psr\Log\LoggerInterface;

require('../../vendor/autoload.php');


class TestLogger implements LoggerInterface
{

    protected $logFile = '/jelixapp/tests/tests/tmp/ldap_tests.log';

    public function emergency($message, array $context = array())
    {
        throw new Exception($message."\n".var_export($context, true));
    }

    public function alert($message, array $context = array())
    {
        throw new Exception($message."\n".var_export($context, true));
    }

    public function critical($message, array $context = array())
    {
        throw new Exception($message."\n".var_export($context, true));
    }

    public function error($message, array $context = array())
    {
        @error_log("LDAP error: ".$message."\n", 3, $this->logFile);
    }

    public function warning($message, array $context = array())
    {
        @error_log("LDAP warning: ".$message."\n", 3, $this->logFile);
    }

    public function notice($message, array $context = array())
    {
        @error_log("LDAP notice: ".$message."\n", 3, $this->logFile);
    }

    public function info($message, array $context = array())
    {
        @error_log("LDAP info: ".$message."\n", 3, $this->logFile);
    }

    public function debug($message, array $context = array())
    {
        @error_log("LDAP debug: ".$message."\n", 3, $this->logFile);
    }

    public function log($level, $message, array $context = array())
    {
        @error_log("LDAP log: ".$message."\n", 3, $this->logFile);
    }
}
