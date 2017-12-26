PHP-FacebookSignedRequest
=========================

Validates that a signed request was passed using the correct algorithm, by Facebook, parses the request, and gives quick access to the resulting data.

### Example

``` php
<?php

    // Example of deauthorize callback
    $signedRequest = $_POST['signed_request'];
    $facebookAppSecret = 'olivernassar';
    $signedRequest = new FacebookSignedRequest(
        $signedRequest,
        $facebookAppSecret
    );
    $data = $signedRequest->getData();
    echo 'Deauthorizing Facebook user ID:' . ($data['user_id']);
    exit(0);

```

The above will throw an exception if the algorithm that the signed request
was signed using is not valid, or if the signed request is not encoded to
match your application's secret key.
