<?php

ini_set('display_errors' , true);

require __DIR__ . "/vendor/autoload.php";



$secretKey = 'Dd0vT3O1tAEzUCu2Sanha7gSMao3yTIKMVFpCL9uRWnmwAVOt8ZjfcUcBihlLrQU';
$jwtManager = new \App\JwtManager($secretKey);


echo "<h2 style='width: 100%;text-align: center'>Jwt Token Tester</h2><hr>";


echo "<h3>The server private Key :</h3>";
echo "<p>{$secretKey}</p>";
echo "<br><br><br>";




$dataToEncode = ['user_id' => 123, 'username' => 'john_doe'];
$jsonDataToEncode = json_encode($dataToEncode);
echo "<h3>The json data</h3>";
echo "<p>{$jsonDataToEncode}</p>";
echo "<br><br><br>";



$token = $jwtManager->generateToken($dataToEncode);
echo "<h3>Generated Token: </h3>";
echo "<p>{$token}</p>";
echo "<br><br><br>";




$decodedData = $jwtManager->validateToken($token);
$jsonDecodedData = json_encode($decodedData);
echo "<h3>Decoded data: </h3>";
echo "<p>{$jsonDecodedData}</p>";
echo "<br><br><br>";



$jsonDecodedData = json_encode($decodedData);
echo "<h3>Validate Data</h3>";
$status = $jsonDecodedData === $jsonDecodedData ? 'OK' : "FAIL";

if ($jsonDecodedData === $jsonDecodedData)
    echo "<p style='background-color: green'>OK</p>";
else
    echo "<p style='background-color: red'>FAIL</p>";
