<?php

require 'vendor/autoload.php';

use MemberSuite\Client;

$client = new MemberSuite\Client();
$client->setMsAuth([...]);

// Receive an SSO token (reverse SSO).
$token = $_POST['Token'];

// The token is base64 encoded.
$de_base64_token = base64_decode($token);

// Sign the decoded token.
$signature = $client->msDigitalSignature($de_base64_token);

$r = $client->LoginWithToken([
  'securityToken' => $de_base64_token,
  'signingCertificateId' => $client->CertificateId,
  'signature' => $signature,
]);

if ($r->SessionID) {
  // Do something.
}
