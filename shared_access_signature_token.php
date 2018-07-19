<?php

/**
* Generate a token to access the Azure API that will expired in 1 month.
* @author James M. Zhou
*/
function generateSASToken($identifier, $key, $expire = 1) {
	$date = mktime(0, 0, 0, date("m") + $expire, date("d"), date("Y"));
	$ex = date("Y-m-d", $date)."T". date("H:i:s").".0000000";

	$signature = "%s\n%s";
	$token = "SharedAccessSignature uid=%s&ex=%s&sn=%s";
	$hashcode = hash_hmac('sha512', utf8_encode(sprintf($signature, $identifier, $ex)), utf8_encode($key), FALSE);
	$hashcode = hex2bin($hashcode);
	$hashcode = base64_encode($hashcode);

	$token = sprintf($token, $identifier, $ex, $hashcode);
	
	return $token;
}
