<?php

/**
 * MemberSuite SOAP client.
 */
class MsClient extends SoapClient {

  private $AccessKeyId;
  private $AssociationId;
  private $SecretKey;
  private $private_key;
  /** @var string The certificate ID. */
  public $certificate_id;

  /**
   * Set authentication for the client.
   *
   * @param string $access_id
   *   MemberSuite access ID.
   *
   * @param string $assoc_id
   *   MemberSuite association ID.
   *
   * @param string $secret_key
   *   MemberSuite secret key.
   */
  function setMsAuth($access_id, $assoc_id, $secret_key) {
    $this->AccessKeyId = $access_id;
    $this->AssociationId = $assoc_id;
    $this->SecretKey = $secret_key;
  }

  /**
   * Set the public and private keys for digital signatures.
   *
   * @param string $key
   *   Private key in PEM format. You can use a tool like
   *   https://superdry.apphb.com/tools/online-rsa-key-converter or
   *   https://github.com/MisterDaneel/PemToXml.git to convert the XML key from
   *   MemberSuite.
   *
   * @param string $id
   *   The matching certificate ID from MemberSuite.
   */
  function setMsKeys($key, $id) {
    $this->private_key = $key;
    $this->certificate_id = $id;
  }

  function authenticate($call) {
    $signature = $this->GenerateMessageSignature($call, $this->SecretKey, $this->AssociationId);

    $header = array();
    $header['AccessKeyId'] = $this->AccessKeyId;
    $header['AssociationId'] = $this->AssociationId;
    $header['Signature'] = $signature;

    $soapHeader = new SOAPHeader('http://membersuite.com/schemas', 'ConciergeRequestHeader', $header);
    $this->__setSoapHeaders(array($soapHeader));
  }

  function __call($function_name, $arguments) {
    return $this->__soapCall($function_name, $arguments);
  }

  function __soapCall($function_name, $arguments, $options = NULL, $input_headers = NULL, &$output_headers = NULL) {
    $this->authenticate($function_name);
    try {
      $r = parent::__soapCall($function_name, $arguments, $options, $input_headers, $output_headers);
    } catch (\SoapFault $f) {
      throw $f;
    } catch (\Exception $e) {
      throw $e;
    }

    $prop = "{$function_name}Result";
    if (!empty($r->$prop->Errors->ConciergeError)) {
      trigger_error(t('Error calling MemberSuite @call: @message', array('@call' => $function_name, '@message' => $r->$prop->Errors->ConciergeError[0]->Message)), E_USER_WARNING);
    }
    return $r;
  }

  /**
   * Generate a signature for a method call.
   *
   * @return string
   *   Base64 encoded string.
   */
  public function GenerateMessageSignature($method, $SecretAccessKey, $AssociationId, $SessionId = "") {
    $call = "http://membersuite.com/contracts/IConciergeAPIService/$method";

    $secret = base64_decode($SecretAccessKey);
    $data = "$call$AssociationId$SessionId";

    return base64_encode(hash_hmac('sha1', $data, $secret, TRUE));
  }

  /**
   * Change value types on child key/value pairs (MS quirk).
   *
   * @param type $items
   */
  static function msSetValueTypes(&$items) {
    foreach ($items as &$item) {
      if (is_scalar($item['Value'])) {
        if (is_bool($item['Value'])) {
          $item['Value'] = new SoapVar($item['Value'], XSD_BOOLEAN, 'boolean', 'http://www.w3.org/2001/XMLSchema');
        }
        elseif (!is_numeric($item['Value']) && strtotime($item['Value']) !== FALSE) {
          $item['Value'] = new SoapVar($item['Value'], XSD_DATETIME, 'dateTime', 'http://www.w3.org/2001/XMLSchema');
        }
        else {
          $item['Value'] = new SoapVar($item['Value'], XSD_STRING, 'string', 'http://www.w3.org/2001/XMLSchema');
        }
      }
    }
  }

  /**
   * Generate KeyValueOfstringanyType child elements (MS quirk).
   *
   * @param array $array
   *   Array of keys/values.
   *
   * @return array
   *   Array containing KeyValueOfstringanyType objects.
   */
  static function msGenerateFields($array) {
    $out = array();
    foreach ($array as $key => $value) {
      $out['KeyValueOfstringanyType'][] = array(
        'Key' => $key,
        'Value' => $value,
      );
    }
    MsClient::msSetValueTypes($out['KeyValueOfstringanyType']);
    return $out;
  }

  /**
   * Sign a message, the MemberSuite way.
   *
   * @todo This uses SHA-1 which is insecure: https://shattered.io
   *
   * @param string $data
   *   The data to sign
   * @return mixed
   *   String, or FALSE if signing failed.
   */
  function msDigitalSignature($data) {
    $signature = NULL;
    if (openssl_sign($data, $signature, $this->private_key, OPENSSL_ALGO_SHA1)) {
      return $signature;
    }
    else {
      return FALSE;
    }
  }

}

/**
 * Hold an array of MemberSuite objects.
 */
class MemberSuiteObjects {

  public $MemberSuiteObject;

}

/**
 * Hold a MemberSuite address.
 */
class MemberSuiteAddress {

  public $City;
  public $Country;
  public $Line1;
  public $PostalCode;
  public $State;

}
