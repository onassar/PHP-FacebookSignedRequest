PHP-FacebookSignedRequest
=========================

Validates that a signed request was passed using the correct algorithm, by Facebook, parses the request, and gives quick access to the resulting data.

### Example

``` php
$signedRequest = $_POST['signed_request'];
$facebookAppSecret = 'olivernassar';
$signedRequest = new FacebookSignedRequest($signedRequest, $facebookAppSecret);
$data = $signedRequest->getData();
echo 'Deauthorizing Facebook user ID:' . ($data['user_id']);
exit(0);
```
