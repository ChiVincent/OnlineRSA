<?php

require_once __DIR__.'/../vendor/autoload.php';

use phpseclib\Crypt\RSA;


switch($_GET['method']??'create')
{
    case 'create':
        header('Content-Type: application/json');
        $rsa = new RSA();
        $rsa->setPrivateKeyFormat(RSA::PRIVATE_FORMAT_XML);
        $rsa->setPublicKeyFormat(RSA::PUBLIC_FORMAT_XML);
        $keypair = $rsa->createKey();
        $publickeyPem = fopen(__DIR__.'/../tmp/publickey.xml', 'w');
        $privatekeyPem = fopen(__DIR__.'/../tmp/privatekey.xml', 'w');
        $publickeyXML = fopen(__DIR__.'/../tmp/publickey.pem', 'w');
        $privatekeyXML = fopen(__DIR__.'/../tmp/privatekey.pem', 'w');
        $rsa->loadKey($keypair['privatekey']);
        fwrite($publickeyPem, $keypair['publickey']);
        fwrite($privatekeyPem, $keypair['privatekey']);
        fwrite($publickeyXML, $rsa->getPublicKey());
        fwrite($privatekeyXML, $rsa->getPrivateKey());
        echo json_encode($keypair);
        break;
    case 'encrypt':
        header('Content-Type: application/json');
        $rsa = new RSA();
        $rsa->loadKey(file_get_contents(__DIR__.'/../tmp/publickey.pem'));
        $plaintext = $_POST['plaintext'];
        $ciphertext = $rsa->encrypt($plaintext);
        echo json_encode(['ciphertext' => base64_encode($ciphertext)]);
        break;
    case 'decrypt':
        header('Content-Type: application/json');
        $rsa = new RSA();
        $rsa->loadKey(file_get_contents(__DIR__.'/../tmp/privatekey.pem'));
        $ciphertext = base64_decode($_POST['ciphertext']);
        $plaintext = $rsa->decrypt($ciphertext);
        echo json_encode(['plaintext' => $plaintext]);
        break;
    case 'download':
        if(isset($_GET['file']) && file_exists(__DIR__.'/../tmp/'.$_GET['file']) && in_array($_GET['file'], ['publickey.pem', 'publickey.xml', 'privatekey.pem', 'privatekey.xml']))
        {
            header('Content-type: application/force-download');
            header('Content-Transfer-Encoding: Binary');
            header('Content-Disposition:attachment;filename='.$_GET['file']);
            echo file_get_contents(__DIR__.'/../tmp/'.$_GET['file']);
        }
        else
            die("File Not Found");
        break;
}