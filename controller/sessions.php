<?php

require_once('db.php');
require_once('../model/Response.php');

try {
    $writeDB = DB::connectWriteDB();
} catch (PDOException $ex) {
    error_log('Connection error: ' . $ex, 0);
    $response = new Response();
    $response->setHttpStatusCode(500);
    $response->setSuccess(false);
    $response->addMessage('Database connection error.');
    $response->send();
    exit();
}

if (array_key_exists('sessionid', $_GET)) {

    $sessionid = $_GET['sessionid'];

    if ($sessionid === '' || !is_numeric($sessionid)) {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        ($sessionid == '' ? $response->addMessage('Session ID cannot be blank.') : false);
        (!is_numeric($sessionid) == '' ? $response->addMessage('Session ID must be numeric.') : false);
        $response->send();
        exit();
    }

    if (!isset($_SERVER['HTTP_AUTHORIZATION']) || strlen($_SERVER['HTTP_AUTHORIZATION']) < 1) {
        $response = new Response();
        $response->setHttpStatusCode(401);
        $response->setSuccess(false);
        (!isset($_SERVER['HTTP_AUTHORIZATION']) ? $response->addMessage('Access token is missing from the header.') : false);
        (strlen($_SERVER['HTTP_AUTHORIZATION']) < 1 ? $response->addMessage('Access token cannot be blank.') : false);
        $response->send();
        exit();
    }

    $accessToken = $_SERVER['HTTP_AUTHORIZATION'];

    if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {

        try {
            $query = $writeDB->prepare('DELETE FROM tblsessions WHERE id = :sessionid AND accesstoken = :accesstoken');
            $query->bindParam(':sessionid', $sessionid, PDO::PARAM_INT);
            $query->bindParam(':accesstoken', $accessToken, PDO::PARAM_STR);
            $query->execute();

            $rowCount = $query->rowCount();

            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(400);
                $response->setSuccess(false);
                $response->addMessage('Failed to log out of this session using access token provided.');
                $response->send();
                exit();
            }

            $returnData = array();
            $returnData['session_id'] = intval($sessionid);

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->addMessage('Logged out.');
            $response->setData($returnData);
            $response->send();
            exit();
        } catch (PDOException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage('There was an issue logging out - please try again.');
            $response->send();
            exit();
        }
    } elseif ($_SERVER['REQUEST_METHOD'] === 'PATCH') {

        if ($_SERVER['CONTENT_TYPE'] !== 'application/json') {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage('Content type header not set to JSON.');
            $response->send();
            exit();
        }

        $rawPATCHData = file_get_contents('php://input');

        if (!$jsonData = json_decode($rawPATCHData)) {
            $response = new Response();
            $response->setHttpStatusCode(400);
            $response->setSuccess(false);
            $response->addMessage('Request body is not valid JSON.');
            $response->send();
            exit();
        }

        // check if patch request contains access token
    if(!isset($jsonData->refresh_token) || strlen($jsonData->refresh_token) < 1)  {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        (!isset($jsonData->refresh_token) ? $response->addMessage("Refresh Token not supplied") : false);
        (strlen($jsonData->refresh_token) < 1 ? $response->addMessage("Refresh Token cannot be blank") : false);
        $response->send();
        exit;
      }

        try {
            $refreshToken = $jsonData->refresh_token;

            $query = $writeDB->prepare('SELECT tblsessions.id AS sessionid, tblsessions.userid AS userid, accesstoken, refreshtoken, useractive, loginattempts, accesstokenexpiry, refreshtokenexpiry FROM tblsessions, tblusers WHERE tblusers.id = tblsessions.userid AND tblsessions.id = :sessionid AND tblsessions.accesstoken = :accesstoken AND tblsessions.refreshtoken = :refreshtoken');
            $query->bindParam(':sessionid', $sessionid, PDO::PARAM_INT);
            $query->bindParam(':accesstoken', $accessToken, PDO::PARAM_STR);
            $query->bindParam(':refreshtoken', $refreshToken, PDO::PARAM_STR);
            $query->execute();

            $rowCount = $query->rowCount();

            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(401);
                $response->setSuccess(false);
                $response->addMessage('Access token or refresh token is incorrect for session id.');
                $response->send();
                exit();
            }

            $row = $query->fetch(PDO::FETCH_ASSOC);

            $returned_sessionid = $row['sessionid'];
            $returned_userid = $row['userid'];
            $returned_accesstoken = $row['accesstoken'];
            $returned_refreshtoken = $row['refreshtoken'];
            $returned_useractive = $row['useractive'];
            $returned_loginattempts = $row['loginattempts'];
            $returned_accesstokenexpiry = $row['accesstokenexpiry'];
            $returned_refreshtokenexpiry = $row['refreshtokenexpiry'];

            if ($returned_useractive !== 'Y') {
                $response = new Response();
                $response->setHttpStatusCode(401);
                $response->setSuccess(false);
                $response->addMessage('User account is not active.');
                $response->send();
                exit();
            }

            if ($returned_loginattempts >= 3) {
                $response = new Response();
                $response->setHttpStatusCode(401);
                $response->setSuccess(false);
                $response->addMessage('User account is currently locked out.');
                $response->send();
                exit();
            }

            if (strtotime($returned_refreshtokenexpiry) < time()) {
                $response = new Response();
                $response->setHttpStatusCode(401);
                $response->setSuccess(false);
                $response->addMessage('Refresh token has expired - please log in again.');
                $response->send();
                exit();
            }

            $accessToken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)) . time());
            $refreshToken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)) . time());

            $access_token_expiry_seconds = 1200;
            $refresh_token_expiry_seconds = 1209600;

            $query = $writeDB->prepare('UPDATE tblsessions SET accesstoken = :accesstoken, accesstokenexpiry = date_add(NOW(), INTERVAL :accesstokenexpiryseconds SECOND), refreshtoken = :refreshtoken, refreshtokenexpiry = date_add(NOW(), INTERVAL :refreshtokenexpiryseconds SECOND) WHERE id = :sessionid AND userid = :userid AND accesstoken = :returnedaccesstoken AND refreshtoken = :returnedrefreshtoken');
            $query->bindParam(':userid', $returned_userid, PDO::PARAM_INT);
            $query->bindParam(':sessionid', $returned_sessionid, PDO::PARAM_INT);
            $query->bindParam(':accesstoken', $accessToken, PDO::PARAM_STR);
            $query->bindParam(':accesstokenexpiryseconds', $access_token_expiry_seconds, PDO::PARAM_INT);
            $query->bindParam(':refreshtoken', $refreshToken, PDO::PARAM_STR);
            $query->bindParam(':refreshtokenexpiryseconds', $refresh_token_expiry_seconds, PDO::PARAM_INT);
            $query->bindParam(':returnedaccesstoken', $returned_accesstoken, PDO::PARAM_STR);
            $query->bindParam(':returnedrefreshtoken', $returned_refreshtoken, PDO::PARAM_STR);
            $query->execute();

            $rowCount = $query->rowCount();

            if ($rowCount === 0) {
                $response = new Response();
                $response->setHttpStatusCode(401);
                $response->setSuccess(false);
                $response->addMessage('Access token could not be refreshed - please log in again.');
                $response->send();
                exit();
            }

            $returnedData = array();
            $returnedData['session_id'] = $returned_sessionid;
            $returnedData['access_token'] = $accessToken;
            $returnedData['access_token_expiry'] = $access_token_expiry_seconds;
            $returnedData['refresh_token'] = $refreshToken;
            $returnedData['refresh_token_expiry'] = $refresh_token_expiry_seconds;

            $response = new Response();
            $response->setHttpStatusCode(200);
            $response->setSuccess(true);
            $response->addMessage('Token refreshed.');
            $response->setData($returnedData);
            $response->send();
            exit();
        } catch (PDOException $ex) {
            $response = new Response();
            $response->setHttpStatusCode(500);
            $response->setSuccess(false);
            $response->addMessage('There was an issue refreshing access token - please login again.');
            $response->send();
            exit();
        }
    } else {
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage('Request method not allowed.');
        $response->send();
        exit();
    }
} elseif (empty($_GET)) {

    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        $response = new Response();
        $response->setHttpStatusCode(405);
        $response->setSuccess(false);
        $response->addMessage('Request method not allowed.');
        $response->send();
        exit();
    }

    sleep(1);

    if ($_SERVER['CONTENT_TYPE'] !== 'application/json') {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage('Content type header not set to JSON.');
        $response->send();
        exit();
    }

    $rawPOSTData = file_get_contents('php://input');

    if (!$jsonData = json_decode($rawPOSTData)) {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        $response->addMessage('Request body is not valid JSON.');
        $response->send();
        exit();
    }

    if (!isset($jsonData->username) || !isset($jsonData->password)) {
        $response = new Response();
        $response->setHttpStatusCode(400);
        $response->setSuccess(false);
        (!isset($jsonData->username) ? $response->addMessage('Username not supplied.') : false);
        (!isset($jsonData->password) ? $response->addMessage('Password not supplied.') : false);
        $response->send();
        exit;
    }

    if (strlen($jsonData->username) < 1 || strlen($jsonData->username) > 255 || strlen($jsonData->password) < 1 || strlen($jsonData->password) > 255) {
        $response = new Response();
        $response->setHttpStatusCode(409);
        $response->setSuccess(false);
        (strlen($jsonData->username) < 1 ? $response->addMessage('Username cannot be blank.') : false);
        (strlen($jsonData->username) > 255 ? $response->addMessage('Username must be less than 255.') : false);
        (strlen($jsonData->password) < 1 ? $response->addMessage('Password cannot be blank.') : false);
        (strlen($jsonData->password) > 255 ? $response->addMessage('Password must be less than 255.') : false);
        $response->send();
        exit();
    }

    try {

        $username = $jsonData->username;
        $password = $jsonData->password;

        $query = $writeDB->prepare('SELECT id, fullname, username, password, useractive, loginattempts FROM tblusers WHERE username = :username');
        $query->bindParam(':username', $username, PDO::PARAM_STR);
        $query->execute();

        $rowCount = $query->rowCount();

        if ($rowCount === 0) {
            $response = new Response();
            $response->setHttpStatusCode(401);
            $response->setSuccess(false);
            $response->addMessage('Username or password is incorrect.');
            $response->send();
            exit();
        }

        $row = $query->fetch(PDO::FETCH_ASSOC);

        $returned_id = $row['id'];
        $returned_fullname = $row['fullname'];
        $returned_username = $row['username'];
        $returned_password = $row['password'];
        $returned_useractive = $row['useractive'];
        $returned_loginattempts = $row['loginattempts'];

        if ($returned_useractive !== 'Y') {
            $response = new Response();
            $response->setHttpStatusCode(401);
            $response->setSuccess(false);
            $response->addMessage('Useraccount not active.');
            $response->send();
            exit();
        }

        if ($returned_loginattempts >= 3) {
            $response = new Response();
            $response->setHttpStatusCode(401);
            $response->setSuccess(false);
            $response->addMessage('Useraccount is currently locked out.');
            $response->send();
            exit();
        }

        if (!password_verify($password, $returned_password)) {

            $query = $writeDB->prepare('UPDATE tblusers SET loginattempts = loginattempts+1 WHERE id = :id');
            $query->bindParam(':id', $returned_id, PDO::PARAM_INT);
            $query->execute();

            $response = new Response();
            $response->setHttpStatusCode(401);
            $response->setSuccess(false);
            $response->addMessage('Username or password is incorrect.');
            $response->send();
            exit();
        }

        $accessToken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)) . time());
        $refreshToken = base64_encode(bin2hex(openssl_random_pseudo_bytes(24)) . time());

        $access_token_expiry_seconds = 1200;
        $refresh_token_expiry_seconds = 1209600;
    } catch (PDOException $ex) {
        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage('There was an issue loggin in.');
        $response->send();
        exit();
    }

    try {
        $writeDB->beginTransaction();

        $query = $writeDB->prepare('UPDATE tblusers SET loginattempts = 0 WHERE id = :id');
        $query->bindParam(':id', $returned_id, PDO::PARAM_INT);
        $query->execute();

        $query = $writeDB->prepare('INSERT INTO tblsessions (userid, accesstoken, accesstokenexpiry, refreshtoken, refreshtokenexpiry) values (:userid, :accesstoken, date_add(NOW(), INTERVAL :accesstokenexpiryseconds SECOND), :refreshtoken, date_add(NOW(), INTERVAL :refreshtokenexpiryseconds SECOND))');
        $query->bindParam(':userid', $returned_id, PDO::PARAM_INT);
        $query->bindParam(':accesstoken', $accessToken, PDO::PARAM_STR);
        $query->bindParam(':accesstokenexpiryseconds', $access_token_expiry_seconds, PDO::PARAM_INT);
        $query->bindParam(':refreshtoken', $refreshToken, PDO::PARAM_STR);
        $query->bindParam(':refreshtokenexpiryseconds', $refresh_token_expiry_seconds, PDO::PARAM_INT);
        $query->execute();

        $lastSessionID = $writeDB->lastInsertId();

        $writeDB->commit();

        $returnData = array();
        $returnData['session_id'] = intval($lastSessionID);
        $returnData['access_token'] = $accessToken;
        $returnData['access_token_expires_in'] = $access_token_expiry_seconds;
        $returnData['refresh_token'] = $refreshToken;
        $returnData['refresh_token_expires_in'] = $refresh_token_expiry_seconds;

        $response = new Response();
        $response->setHttpStatusCode(201);
        $response->setSuccess(true);
        $response->addMessage('Login ok.');
        $response->setData($returnData);
        $response->send();
        exit();
    } catch (PDOException $ex) {
        $writeDB->rollBack();
        $response = new Response();
        $response->setHttpStatusCode(500);
        $response->setSuccess(false);
        $response->addMessage('There was an issue loggin in - please try again.');
        $response->send();
        exit();
    }
} else {
    $response = new Response();
    $response->setHttpStatusCode(404);
    $response->setSuccess(false);
    $response->addMessage('Endpoint not found.');
    $response->send();
    exit();
}
