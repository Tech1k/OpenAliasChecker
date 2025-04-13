<?php
session_start();

$result = "";
$response = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['domain'])) {
    $raw_domain = $_POST['domain'];

    if (strpos($raw_domain, '@') !== false) {
        $domain = str_replace('@', '.', $raw_domain);
    } else {
        $domain = $raw_domain;
    }

    if (!preg_match('/^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$/', $domain)) {
        $_SESSION['response'] = [
            'error' => true,
            'response' => 'Not a valid domain.',
            'raw_domain' => $raw_domain
        ];
    } else {
        $records = dns_get_record($domain, DNS_TXT);
        $response_data = [];
        $response_data['records'] = [];

        foreach ($records as $record) {
            if (substr($record['txt'], 0, 3) === 'oa1') {
                $this_record = ['oa1' => substr($record['txt'], 4, 3)];
                $record['txt'] = array_map('trim', explode(';', substr($record['txt'], 8)));
                foreach ($record['txt'] as $item) {
                    $this_item = explode('=', $item);
                    if (count($this_item) > 1) {
                        $this_record[$this_item[0]] = $this_item[1];
                    }
                }
                $response_data['records'][] = $this_record;
            }
        }

        if (empty($response_data['records'])) {
            $response_data['error'] = true;
            $response_data['response'] = 'No OA1 (OpenAlias) TXT records were found for this domain.';
        } else {
            $response_data['records_returned'] = count($response_data['records']);
            $response_data['error'] = false;
            $response_data['raw_domain'] = $raw_domain;

            // DNSSEC check
            exec('host -t RRSIG ' . escapeshellarg($domain) . ' 8.8.8.8', $output);
            $response_data['dnssec_verified'] = false;
            foreach ($output as $line) {
                if (stripos($line, 'RRSIG') !== false) {
                    $response_data['dnssec_verified'] = true;
                    break;
                }
            }
        }

        $_SESSION['response'] = $response_data;
    }

    header("Location: " . $_SERVER['PHP_SELF']);
    exit();
}

if (isset($_SESSION['response'])) {
    $response = $_SESSION['response'];
    unset($_SESSION['response']);
}
?>

<!DOCTYPE html>
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<meta name="theme-color" content="#5271ff">
		<link rel="canonical" href="https://openaliaschecker.com"/>
		<meta name="robots" content="index, follow">
		<meta name="description" content="A simple and free tool to check OpenAlias configurations."/>
		<meta name="author" content="Tech1k">
		<title>OpenAlias Checker</title>
		<link rel="shortcut icon" href="/assets/favicon.png"/>
		<meta property="og:title" content="OpenAlias Checker"/>
		<meta property="og:description" content="A simple and free tool to check OpenAlias configurations."/>
		<meta property="og:type" content="website"/>
		<meta property="og:url" content="https://openaliaschecker.com"/>
		<meta property="og:site_name" content="OpenAlias Checker"/>
		<meta name="twitter:card" content="summary"/>
		<meta name="twitter:title" content="OpenAlias Checker"/>
		<meta name="twitter:description" content="A simple and free tool to check OpenAlias configurations."/>
		<link rel="stylesheet" href="/assets/style.css?v=2">
    </head>
    <body id="main">
        <h1>OpenAlias Domain Checker</h1>
        <p>A simple and free tool to check OpenAlias configurations.</p>
        <form method="post">
            <label for="domain">Enter Domain Name:</label><br><br>
            <input type="text" id="domain" name="domain" placeholder="example.com" required>
            <input type="submit" value="Check OpenAlias">
        </form>
        <?php
        if (isset($response)) {
            echo "<div class='result' style='word-break: break-word;'>";
            if (isset($response['error']) && $response['error'] === true) {
                echo "<p><strong>Error:</strong> " . htmlspecialchars($response['response']) . "</p>";
                echo "❌ Your OpenAlias DNS TXT records seem to be invalid.";
            } else {
                echo "<h3>OpenAlias Results for " . htmlspecialchars($response['raw_domain']) . ":</h3>";
                foreach ($response['records'] as $record) {
                    echo "<p><strong>oa1:</strong> " . htmlspecialchars($record['oa1']) . "<br>";
                    foreach ($record as $key => $value) {
                        if ($key != 'oa1') {
                            echo "<strong>" . htmlspecialchars(ucwords(str_replace("_", " ", $key))) . ":</strong> " . htmlspecialchars($value) . "<br>";
                        }
                    }
                    echo "</p>";
                }
                if (isset($response['dnssec_verified'])) {
                    if ($response['dnssec_verified'] === "No") {
                        echo "<p><strong>DNSSEC Verified:</strong> No<br>Notice: your OpenAlias configuration looks valid, but DNSSEC is not enabled on your domain. It is highly recommended to enable DNSSEC as some wallets may not work without it.</p>";
                    } else {
                        echo "<p><strong>DNSSEC Verified:</strong> Yes</p>";
                    }
                }
                echo "✅ Your OpenAlias DNS TXT records look valid.";
            }
            echo "</div>";
        }
        ?>
        <hr>
        <section style="margin-top: 40px;">
            <h2>FAQs</h2>

            <h3>What is this site?</h3>
            <p>This site allows you to verify whether your OpenAlias configuration is valid and matches what you want other people to see.</p>

            <h3>What is OpenAlias?</h3>
            <p>OpenAlias is a TXT DNS record added to a domain that points to a cryptocurrency address, along with simple metadata such as the recipient name and a transaction description.</p>
            <p>To learn more, check out the <a href="https://openalias.org/#implement" target="_blank" rel="noopener noreferrer">OpenAlias implementation guide</a>.</p>

            <h4>Example OpenAlias TXT Record for Bitcoin:</h4>
            <code style="word-break: break-word;">oa1:btc recipient_address=bc1q33pgz4dsal3h2ahkhe8ty0e7z32ttteyz4tx2d; recipient_name=OpenAliasChecker; tx_description=Donate to OpenAlias Checker</code>

            <h3>Do you log the domains I check?</h3>
            <p>No, we do not log the domain(s) you check on this site. However, your IP address may be temporarily logged by our web server for abuse prevention purposes.</p>

            <h3>How can I support this site?</h3>
            <p>If you'd like to support the upkeep of this site, you can do so via Bitcoin, Litecoin or Monero to openaliaschecker.com or tech1k.com via OpenAlias in a supported wallet.</p>

            <h3>Is this site open source?</h3>
            <p>Yes! You can find the full source code on GitHub: <a href="https://github.com/Tech1k/OpenAliasChecker" target="_blank" rel="noopener noreferrer">github.com/Tech1k/OpenAliasChecker</a>.</p>
        </section>
        <p style="font-size: 0.9em; color: gray;">
            Disclaimer: This tool is provided "as is" with no warranties. Use at your own risk. Always double-check results with your own DNS tools when configuring critical records.
        </p>
        <br/>
    </body>
</html>
