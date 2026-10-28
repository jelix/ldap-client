<?php

use Psr\Log\LoggerInterface;

require('../../vendor/autoload.php');


class TestLogger implements LoggerInterface
{

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
        throw new Exception($message."\n".var_export($context, true));
    }

    public function warning($message, array $context = array())
    {
        echo "LDAP warning: ".$message."\n";
    }

    public function notice($message, array $context = array())
    {
        // TODO: Implement notice() method.
    }

    public function info($message, array $context = array())
    {
        echo "LDAP info: ".$message."\n";
    }

    public function debug($message, array $context = array())
    {
        // TODO: Implement debug() method.
    }

    public function log($level, $message, array $context = array())
    {
        echo "LDAP log: ".$message."\n";
    }
}