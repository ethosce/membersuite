<?php

require 'vendor/autoload.php';

use MemberSuite\Client;

$client = new MemberSuite\Client();

// Access ID and secret.
$access_id = 'jgxNi00NWQyYTUwNC1lZTQxYjU';
$secret_key = 'MTE2ODljZjktMjgxNi00NWQyLWE1MDQtZWU0MWI1ODM3OTFhCg';

// Association info.
$assoc_id = '11689cf9-2816-45d2-a504-ee41b583791a';
$assoc_key = '30303';

// Signing key/certificate.
$certificate_id = 'WU0MWI1ODM3OTFhCg';
// You can use a tool like https://github.com/MisterDaneel/PemToXml.git to
// convert the XML key from MemberSuite.
$private_key = '-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDTTPFwSiVbQMiA
Dv7Hz4fdNTdUWOM/5ek5haG99iqe2D6DQqW6kWVRkFkEoBq0WdHq2jfcuCgFxEDz
EviHtiPX8ZGX59XXacQrUeUtUwVriXf086A6l3grF8NOVOWkMWYadZosPNFQwaf4
O89f4rTusacdzXH/OER62JAY9464ci3LXfyjrFIQGAFYb0YyxA/lWUKvBICNh8TN
XU8XAyzIM30/YQfmA3VbqHcIgLrPSWQO6KK9f9VyTX4705753lLIYc4JgIYGL7TU
I54c272q2cf6rWGIX1PtfVzVv3fdTqPyjAwBCD3Z2zQLaA1P2gCRbpAb4+fBHmrJ
IhT7UcKhAgMBAAECggEAW74xqkaXN6rGI0vfdZP28qXTcyzw5mKFw/LwihEi6jsL
0WQTnxDYA/T/oZF+ZsYE7cp3rL7MqcxPQvr+q7X6lB0P0PvZDiGfCgwRzH8agFl8
mv9Yl3gCtfsoUo9r8cF9Con7Oa/iVgTvUElvvbsqQeUioT79ewnMOeZjkmOSNSSb
mQxP+wIcSpHv6LVnuUKCZl/UOmzC7lD/dokqVK6qzyyAcl7m8nMF7TaJg5oCzZor
CgUw6wRzxgNaZbdD/4pHiyubuldpjXR3htcOn1cvWWOPGx1IWhh13TkeUlL8f5/D
hsefnshVong+rafMfqn+KrZflzKgc4fyl/gPjsILDQKBgQD6RyBe+xpBk+KfCOBE
wySJE7gu46KxQvRFEZyYtsk5Eb8pDYX7kV3ymb1A+5kPKeARHmNabtX1BnkTlVw4
Lm1sXwDiHWp5FBC90bUFKRGJtjD+n5kOfkciuOIUqhs8jytHR5I/rG+jmnAMpqOX
anqweMkTf8ufQ8kydrV/elxXYwKBgQDYIa7dlfuOejD0D1QgqE8byWCQ2tIH6Bch
j4Blf00FP6aUIpppzYRWMeVkiz2H7tDAuV54rjIfvEt07H/caOg2iCehuimTA+Xv
ad7RUmHqnBjV5BzwYO6VQE+2zGZtGvHcamMsJnYtc+7kAnBJUoZAf6vc14ZcR+Oe
OApBNzUnKwKBgQDWGA4K8gaN3nHX1YHzkHMqh6HhCn1b4YiPpPcuc/5CQXojJhxd
DQcuxnDsq81M+WdhfXtEGtgQGI9uPzB6Js0YDVT2GG/CT3Xayw9s8Kq+AQp8Zg5K
JZ+4hitvvew6q8Y73W+v5FRDwZLkX5BFsKJvX4OymHmZLiVoc7/i4ssnPQKBgQC1
lU8KIhlwMd7xHfPLYDzelokICqBNPkQ40QzJuXNnRnvYl13uKFnX5SHaIFX4378J
PHRPpeK84QDwYkZmUslOD4RkjzigqLTFOciXSsSzTKRdB8L8fiPUx2xxozcm0W2E
hul9TW8abv21GQtnvurGQ72L1JOw8kEdS+3prs18cwKBgFnPMX9D3eWYOd7TDhSS
IN+VdPa2H/f205jaSO5u7hliApPGCLWAQxVOc+N4wHvHdA6PUeHOVYaGEwyrJcNn
1/Y57nYy3Z2qwLU6AqanlQxLJEUwyaqgV85ha60csFnWi19470sETEU3wbGISpax
ZQWzo8MmVp2Q1/UDN9ZEtA6K
-----END PRIVATE KEY-----';

$client->setMsAuth($access_id, $secret_key, $assoc_id, $assoc_key, $certificate_id, $private_key);

// Basic API call.
$response = $client->WhoAmI();

// Signed API call.
$loginAs = 'myuser@example.com';
$signature = $client->msDigitalSignature($loginAs);

$r = $client->CreatePortalSecurityToken([
  'portalUserName' => $loginAs,
  'signingCertificateId' => $client->CertificateId,
  'signature' => $signature,
  ]);

// Saving objects with KeyValueOfstringanyType fields.
$fields = array(
  'SomeField' => '12345',
  'SomeDate' => '2018-01-01',
  'Flag' => TRUE,
);

$client->Save([
  'objectToSave' => [
    'ClassType' => 'SomeClass',
    'Fields' => $client->msGenerateFields($fields),
  ]]
);
