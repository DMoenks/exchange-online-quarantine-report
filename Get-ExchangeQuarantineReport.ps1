[OutputType([string])]
param ([Parameter(Mandatory=$true)]
        [string]$credentialName,
        [Parameter(Mandatory=$true)]
        [string]$recipientAddress,
        [Parameter(Mandatory=$true)]
        [string]$releaseRequestRecipientAddress,
        [Parameter(Mandatory=$true)]
        [bool]$advanced)

$catTranslation = @{'BULK' = 'Bulk';
                    'DIMP' = 'Domain impersonation';
                    'GIMP' = 'Mailbox intelligence based impersonation';
                    'HPHSH' = 'High confidence phishing';
                    'HPHISH' = 'High confidence phishing';
                    'HSPM' = 'High confidence spam';
                    'MALW' = 'Malware';
                    'PHSH' = 'Phishing';
                    'SPM' = 'Spam';
                    'SPOOF' = 'Spoofing';
                    'UIMP' = 'User impersonation';
                    'AMP' = 'Anti-malware';
                    'SAP' = 'Safe attachments';
                    'OSPM' = 'Outbound spam'}
$sfvTranslation = @{'BLK' = 'Blocked, mailbox blocked sender';
                    'BULK' = 'Bulk, spam filtering';
                    'NSPM' = 'NoSpam, spam filtering';
                    'SFE' = 'Skipped, mailbox safe sender';
                    'SKA' = 'Skipped, global safe sender';
                    'SKB' = 'Blocked, global blocked sender';
                    'SKI' = 'Skipped, intra-organization';
                    'SKN' = 'Skipped, transport rule';
                    'SKQ' = 'Quarantine release';
                    'SKS' = 'Spam, transport rule';
                    'SPM' = 'Spam, spam filtering'}

$style = @"
<style>
table {
    border: none;
    border-collapse: collapse;
}
th, td {
    text-align: left;
    vertical-align: top;
}
td.results {
    padding-left: 4pt;
}
td.request, td.review {
    padding: 4pt;
}
td.review {
    background-color: #483d8b;
}
td.request {
    background-color: #696969;
}
td.pass, td.neutral, td.fail {
    border-left: solid 4pt;
}
td.pass {
    border-color: #006400;
}
td.neutral {
    border-color: #b8860b;
}
td.fail {
    border-color: #8b0000;
}
a {
    text-decoration: none;
}
a.quarantine {
    color: #f5f5f5;
}
</style>
"@

Connect-ExchangeOnline -Credential (Get-AutomationPSCredential -Name $credentialName) -CommandName 'Get-QuarantineMessage','Get-QuarantineMessageHeader' | Out-Null

$quarantineEntries = Get-QuarantineMessage -RecipientAddress $recipientAddress | Where-Object{$_.Released -eq $false} | Sort-Object SenderAddress, ReceivedTime | Group-Object SenderAddress
if ($quarantineEntries.Count -gt 0)
{
    $output = [System.Text.StringBuilder]::new()
    $output.AppendLine("<p>") | Out-Null
    $output.AppendLine($style) | Out-Null
    foreach ($quarantineEntry in $quarantineEntries)
    {
        $sender = $quarantineEntry.Name
        
        $output.AppendLine(@"
<table>
<tr>
<td>
<table>
<tr>
<td>
<table>
<tr>
<td>Sender:</td>
<td>$sender</td>
</tr>
</table>
</td>
</tr>
"@) | Out-Null
        foreach ($quarantineEntryEmail in $quarantineEntry.Group)
        {
            $subject = $quarantineEntryEmail.Subject
            $receivedDate = $quarantineEntryEmail.ReceivedTime
            $expiresDate = $quarantineEntryEmail.Expires
            $id = $quarantineEntryEmail.Identity
            
            $output.AppendLine(@"
<tr>
<td>
<table>
<tr>
<td class='results'>
<table>
<tr>
<th>Subject:</th>
<th>$subject</th>
</tr>
<tr>
<td>Received:</td>
<td>$receivedDate</td>
</tr>
<tr>
<td>Expires:</td>
<td>$expiresDate</td>
</tr>
</table>
<table>
<tr>
<td class='review'>
<a href='https://security.microsoft.com/quarantine?id=$([System.Web.HttpUtility]::UrlEncode($id))' target='_blank' class='quarantine'>Review</a>
</td>
<td />
<td class='request'>
<a href='mailto:$releaseRequestRecipientAddress?subject=$([System.Web.HttpUtility]::UrlEncode("Please review and release email '$subject' from quarantine"))&body=$([System.Web.HttpUtility]::UrlEncode("Subject: $subject"))%0D%0A$([System.Web.HttpUtility]::UrlEncode("Received: $receivedDate"))%0D%0A$([System.Web.HttpUtility]::UrlEncode("Expires: $expiresDate"))%0D%0A$([System.Web.HttpUtility]::UrlEncode("Review link: https://security.microsoft.com/quarantine?id=$id"))' target='_blank' class='quarantine'>Request release</a>
</td>
</tr>
</table>
"@) | Out-Null
            if ($advanced)
            {
                # Get email headers
                $header = ($quarantineEntryEmail | Get-QuarantineMessageHeader).Header
                # Match email headers
                $antiSpam = [regex]::Match($header, 'X-Microsoft-Antispam:\s+.+')
                $antiSpamReport = [regex]::Match($header, 'X-Forefront-Antispam-Report:\s+.+')
                $authentication = [regex]::Match($header, 'Authentication-Results:[\s\S]+?;compauth=\w+\s+reason=\d+')
                # Match header values
                $bcl = [regex]::Match($antiSpam, 'BCL:(\d);').Groups[1].Value
                $scl = [regex]::Match($antiSpamReport, 'SCL:(\d);').Groups[1].Value
                $cat = [regex]::Match($antiSpamReport, 'CAT:(\w+);').Groups[1].Value
                $sfv = [regex]::Match($antiSpamReport, 'SFV:(\w+);').Groups[1].Value
                $spf = [regex]::Match($authentication, 'spf=(\w+)').Groups[1].Value
                $dkim = [regex]::Match($authentication, 'dkim=(\w+)').Groups[1].Value
                $dmarc = [regex]::Match($authentication, 'dmarc=(\w+)').Groups[1].Value
                $compauthResult = [regex]::Match($authentication, 'compauth=(\w+)\s+reason=\d+').Groups[1].Value
                $compauthReason = [regex]::Match($authentication, 'compauth=\w+\s+reason=(\d+)').Groups[1].Value
                
                if ($bcl -in 0..3)
                {
                    $bclCategory = 'pass'
                }
                elseif ($bcl -in 4..7)
                {
                    $bclCategory = 'neutral'
                }
                elseif ($bcl -in 8..9)
                {
                    $bclCategory = 'fail'
                }
                else
                {
                    $bclCategory = ''
                }
                if ($scl -in 0..4)
                {
                    $sclCategory = 'pass'
                }
                elseif ($scl -in 5..6)
                {
                    $sclCategory = 'neutral'
                }
                elseif ($scl -in 7..9)
                {
                    $sclCategory = 'fail'
                }
                else
                {
                    $sclCategory = ''
                }
                switch ($spf)
                {
                    'pass'
                    {
                        $spfCategory = 'pass'
                    }
                    'fail'
                    {
                        $spfCategory = 'fail'
                    }
                    Default
                    {
                        $spfCategory = 'neutral'
                    }
                }
                switch ($dkim)
                {
                    'pass'
                    {
                        $dkimCategory = 'pass'
                    }
                    'fail'
                    {
                        $dkimCategory = 'fail'
                    }
                    Default
                    {
                        $dkimCategory = 'neutral'
                    }
                }
                switch -Wildcard ($dmarc)
                {
                    '*pass'
                    {
                        $dmarcCategory = 'pass'
                    }
                    'fail'
                    {
                        $dmarcCategory = 'fail'
                    }
                    Default
                    {
                        $dmarcCategory = 'neutral'
                    }
                }
                switch -Wildcard ($compauthResult)
                {
                    '*pass'
                    {
                        $compauthCategory = 'pass'
                    }
                    'fail'
                    {
                        $compauthCategory = 'fail'
                    }
                    Default
                    {
                        $compauthCategory = 'neutral'
                    }
                }

                $output.AppendLine(@"
<table>
<tr>
<td class='results'>
<table>
<tr>
<th colspan='2'>Filtering results</th>
</tr>
<tr>
<td>
<a href='https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/bulk-complaint-level-values?view=o365-worldwide'>BCL:</a>
</td>
<td class='$bclCategory'>$bcl</td>
</tr>
<tr>
<td>
<a href='https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/spam-confidence-levels?view=o365-worldwide'>SCL:</a>
</td>
<td class='$sclCategory'>$scl</td>
</tr>
<tr>
<td>
<a href='https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-message-headers?view=o365-worldwide#x-forefront-antispam-report-message-header-fields'>CAT:</a>
</td>
<td>$($catTranslation[$cat])</td>
</tr>
<tr>
<td>
<a href='https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-message-headers?view=o365-worldwide#x-forefront-antispam-report-message-header-fields'>SFV:</a>
</td>
<td>$($sfvTranslation[$sfv])</td>
</tr>
</table>
</td>
<td class='results'>
<table>
<tr>
<th colspan='2'>Authentication results</th>
</tr>
<tr>
<td>
<a href='https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-message-headers?view=o365-worldwide#authentication-results-message-header'>SPF:</a>
</td>
<td class='$spfCategory'>$spf</td>
</tr>
<tr>
<td>
<a href='https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-message-headers?view=o365-worldwide#authentication-results-message-header'>DKIM:</a>
</td>
<td class='$dkimCategory'>$dkim</td>
</tr>
<tr>
<td>
<a href='https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-message-headers?view=o365-worldwide#authentication-results-message-header'>DMARC:</a>
</td>
<td class='$dmarcCategory'>$dmarc</td>
</tr>
<tr>
<td>
<a href='https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-message-headers?view=o365-worldwide#authentication-results-message-header'>COMPAUTH:</a>
</td>
<td class='$compauthCategory'>$compauthResult/$compauthReason</td>
</tr>
</table>
</td>
</tr>
</table>
"@) | Out-Null
            }
            $output.AppendLine(@"
</td>
</tr>
</table>
</td>
</tr>
"@) | Out-Null
        }
        $output.AppendLine(@"
</table>
</td>
</tr>
</table>
"@) | Out-Null
    }
    $output.AppendLine("</p>") | Out-Null
    $output.ToString() | Write-Output
}
else
{
    'N/A' | Write-Output
}
