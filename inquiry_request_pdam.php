<?php

$clientId = "test_apikko_rtonline";
$clientSecret = "66Gw0JiWMhv7GNH253mDjrRvc4uNa655";
$privateKeyPath = __DIR__ . "/private_key.pem"; 

$tokenUrl = "https://dev-mkmsp.mkm.id/token?dur=30&mcc=6025";
$inquiryUrl = "https://dev-mkmsp.mkm.id/h2hmkm"; 

function minify_json($json) {
    return json_encode(json_decode($json, true), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

$data = $_POST;

if (!is_array($data)) {
    http_response_code(400);
    echo json_encode(["error" => "Invalid JSON input"]);
    exit;
}

$timestamp = date("c");
$hmacContent = $clientId . ":" . $timestamp;
$hmacHash = base64_encode(hash_hmac('sha256', $hmacContent, $clientSecret, true));

$signingString = "MKM-AUTH-1.0/$hmacHash/$timestamp";
$privateKey = file_get_contents($privateKeyPath);
if (!$privateKey) {
    http_response_code(500);
    echo json_encode(["error" => "Private key not found"]);
    exit;
}

openssl_sign($signingString, $binarySignature, $privateKey, OPENSSL_ALGO_SHA256);
$signature = base64_encode($binarySignature);

$headers = [
    "Authorization: MKM-AUTH-1.0",
    "X-Client-Id: $clientId",
    "X-Timestamp: $timestamp",
    "X-Signature: $signature"
];

$ch = curl_init($tokenUrl);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$tokenResponse = curl_exec($ch);
$curlError = curl_error($ch);
curl_close($ch);

if (!$tokenResponse) {
    http_response_code(500);
    echo json_encode(["error" => "Curl error on token request", "details" => $curlError]);
    exit;
}

$tokenData = json_decode($tokenResponse, true);
if (empty($tokenData["Token"])) {
    http_response_code(401);
    echo json_encode(["error" => "Token retrieval failed", "response" => $tokenResponse]);
    exit;
}

$token = $tokenData["Token"];

$payload = [
    "Action" => "inquiry",
    "ClientId" => $clientId,
    "MCC" => $data["mcc"] ?? "6025",
    "KodeProduk" => $data["kode_produk"] ?? "",
    "NomorPelanggan" => $data["nomor_pelanggan"] ?? "",
    "Versi" => $data["versi"] ?? "2"
];

$body = minify_json(json_encode($payload));
$timestamp = date("c");

$contentToSign = $token . "/" . $body . "/" . $timestamp;
$signature = base64_encode(hash_hmac('sha256', $contentToSign, $clientSecret, true));

$inquiryHeaders = [
    "Content-Type: application/json",
    "Authorization: Bearer $token",
    "X-Timestamp: $timestamp",
    "X-Signature: $signature"
];

$ch = curl_init($inquiryUrl);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
curl_setopt($ch, CURLOPT_HTTPHEADER, $inquiryHeaders);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlError = curl_error($ch);
curl_close($ch);

if (!$response) {
    http_response_code(500);
    echo json_encode(["error" => "Curl error on inquiry request", "details" => $curlError]);
    exit;
}

header("Content-Type: application/json");
http_response_code($httpCode);
echo $response;

?>
