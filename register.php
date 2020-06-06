<?php
// Change this to your connection info.
$DATABASE_HOST = 'localhost';
$DATABASE_USER = 'root';
$DATABASE_PASS = '';
$DATABASE_NAME = 'phplogin';
// Try and connect using the info above.
$con = mysqli_connect($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);
if (mysqli_connect_errno()) {
    // If there is an error with the connection, stop the script and display the error.
    exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}
// Now we check if the data was submitted, isset() function will check if the data exists.
if (!isset($_POST['first_name'],$_POST['last_name'],$_POST['username'], $_POST['email'], $_POST['password'], $_POST['confirm_password'])) {
    // Could not get the data that should have been sent.
    exit('Please complete the registration form!');
}
// Make sure the submitted registration values are not empty.
if (empty($_POST['first_name']) || empty($_POST['last_name']) || empty($_POST['username']) || empty($_POST['email']) || empty($_POST['password']) || empty($_POST['confirm_password'])) {
    // One or more values are empty.
    exit('Please complete the registration form');
}
//check for email validation
if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
    exit('Email is not valid!');
}
//validate username
if (preg_match('/[A-Za-z0-9]+/', $_POST['username']) == 0) {
    exit('Username is not valid!');
}
//validate password
if (strlen($_POST['password']) > 20 || strlen($_POST['password']) < 5) {
    exit('Password must be between 5 and 20 characters long!');
}
//check the password and confirm password match
if ($_POST['password'] !== $_POST['confirm_password']){
    exit('Passwords do not match');
}
// We need to check if the account with that username exists.
if ($stmt = $con->prepare('SELECT id, password FROM accounts WHERE email = ?')) {
    // Bind parameters (s = string, i = int, b = blob, etc), hash the password using the PHP password_hash function.
    $stmt->bind_param('s', $_POST['email']);
    $stmt->execute();
    $stmt->store_result();
    // Store the result so we can check if the account exists in the database.
    if ($stmt->num_rows > 0) {
        // Username already exists
        echo 'User with this email already exists, please choose another!';
    }
        // Username doesnt exists, insert new account
            elseif ($stmt = $con->prepare('INSERT INTO accounts (username, password, email, activation_code, first_name, last_name) VALUES (?, ?, ?, ?, ?, ?)')) {
            // We do not want to expose passwords in our database, so hash the password and use password_verify when a user logs in.
            $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
            $uniqid = uniqid();
            $stmt->bind_param('ssssss', $_POST['username'], $password, $_POST['email'], $uniqid, $_POST['first_name'], $_POST['last_name']);
            $stmt->execute();
                $from    = 'carolgitonga45@gmail.com';
                $subject = 'Account Activation Required';
                $headers = 'From: ' . $from . "\r\n" . 'Reply-To: ' . $from . "\r\n" . 'X-Mailer: PHP/' . phpversion() . "\r\n" . 'MIME-Version: 1.0' . "\r\n" . 'Content-Type: text/html; charset=UTF-8' . "\r\n";
                $activate_link = 'http://localhost/SLAUI/activate.php?email=' . $_POST['email'] . '&code=' . $uniqid;
                $message = '<p>Please click the following link to activate your account:
                            <a href="' . $activate_link . '">' . $activate_link . '</a></p>';
                mail($_POST['email'], $subject, $message, $headers);
                echo 'Please check your email to activate your account!';
        } else {
            // Something is wrong with the sql statement, check to make sure accounts table exists with all 5 fields.
            echo 'Could not prepare statement!';
        }
    $stmt->close();
} else {
    // Something is wrong with the sql statement, check to make sure accounts table exists with all 3 fields.
    echo 'Could not prepare statement!';
}
$con->close();
?>
