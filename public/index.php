<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>線上 RSA 加解密</title>
    <!-- Latest compiled and minified CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">
    <style>
        body { padding-top: 70px; }
    </style>
</head>
<body>
    <header>
        <nav class="navbar navbar-default navbar-fixed-top">
            <div class="container-fluid">
                <div class="navbar-header">
                    <a class="navbar-brand" href="#">testRSA</a>
                </div>
                <div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">
                    <ul class="nav navbar-nav">
                        <li><a href="#" onclick="genKey()">生成公私鑰</a></li>
                        <li><a href="#" onclick="encrypt()">加密</a></li>
                        <li><a href="#" onclick="decrypt()">解密</a></li>
                    </ul>
                </div>
            </div>
        </nav>
    </header>
    <div class="container" id="keypair">
        <h1>金鑰</h1>
        <div class="col-md-6">
            <h3>公鑰</h3>
            <button class="btn btn-primary" onclick="download('publickey.pem')">下載 PEM</button>
            <button class="btn btn-success" onclick="download('publickey.xml')">下載 XML</button>
            <textarea id="publickey" class="form-control" rows="20"></textarea>
        </div>
        <div class="col-md-6">
            <h3>私鑰</h3>
            <button class="btn btn-primary" onclick="download('privatekey.pem')">下載 PEM</button>
            <button class="btn btn-success" onclick="download('privatekey.xml')">下載 XML</button>
            <textarea id="privatekey" class="form-control" rows="20"></textarea>
        </div>
    </div>
    <hr/>
    <div class="container" id="encrypt">
        <h1>加密</h1>
        <div class="col-md-6">
            <h3>原文</h3>
            <textarea id="plaintext" class="form-control" rows="10"></textarea>
        </div>
        <div class="col-md-6">
            <h3>密文(PHP)</h3>
            <textarea id="ciphertext-php" class="form-control" rows="10"></textarea>
        </div>
    </div>
    <div class="container" id="decrypt">
        <h1>解密</h1>
        <div class="col-md-6">
            <h3>密文</h3>
            <textarea id="ciphertext" rows="10" class="form-control"></textarea>
        </div>
        <div class="col-md-6">
            <h3>原文（PHP）</h3>
            <textarea id="plaintext-php" rows="10" class="form-control"></textarea>
        </div>
    </div>

    <!-- Latest compiled and minified JavaScript -->
    <script src="https://code.jquery.com/jquery-2.2.3.min.js" integrity="sha256-a23g1Nt4dtEYOj7bR+vTu7+T8VP13humZFBJNIYoEJo="   crossorigin="anonymous"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js" integrity="sha384-0mSbJDEHialfmuBBQP6A4Qrprq5OVfW37PRR3j5ELqxss1yVqOtnepnHVP9aJ7xS" crossorigin="anonymous"></script>
    <script>
        function genKey()
        {
            fetch('/action.php?method=create')
                .then(response => response.json())
                .then(json => {
                    $('#publickey').val(json.publickey);
                    $('#privatekey').val(json.privatekey);
                })
                .catch(ex => console.error('parsing failed', ex);
        }

        function encrypt()
        {
            var form = new FormData();
            form.append('plaintext', $('#plaintext').val());
            fetch('/action.php?method=encrypt', {
                method: 'POST',
                body: form
            })
                .then(response => response.json());
                .then(json => $('#ciphertext-php').val(json.ciphertext));
                .catch(ex => console.log('parsing failed', ex));
        }

        function decrypt()
        {
            var form = new FormData();
            form.append('ciphertext', $('#ciphertext').val());
            fetch('/action.php?method=decrypt', {
                method: 'POST',
                body: form
            })
                .then(response => response.json());
                .then(json => $('#plaintext-php').val(json.plaintext));
                .catch(ex => console.error('parsing failed', ex));
        }

        function download(filename)
        {
            let url = `/action.php?method=download&file=${filename}`;
            window.open(url, '_blank');
        }
    </script>
</body>
</html>
