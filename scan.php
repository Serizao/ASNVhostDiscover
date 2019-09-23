<?php
ini_set('max_execution_time', 0);
ini_set('memory_limit', -1);




$host = $subnet = $network = $mask = $ports = $verbose = $domaine = $checkVhost = $burp = $onlyVhost ='';
$sizeVariation = '100';
for($i=0;$i<count($argv);$i++){
  if(strstr( $argv[$i], '--host=' )) $host = explode('=',$argv[$i])[1];
  if(strstr( $argv[$i], '--network=' )){
    $subnet = explode('=',$argv[$i])[1];
    $temp =  explode('/',$subnet);
    $network = $temp[0];
    $mask = $temp[1];
  }
  if(strstr( $argv[$i], '--ports=' )) $ports = explode('=',$argv[$i])[1];
  if(strstr( $argv[$i], '--check-name=' )) $domaine = explode('=',$argv[$i])[1];
  if(strstr( $argv[$i], '--check-name-file=' )) $domaine = explode("\r\n",file_get_contents(explode('=',$argv[$i])[1]));
  if(strstr( $argv[$i], '--verbose' )) $verbose=true;
  if(strstr( $argv[$i], '--check-vhost' )) $checkVhost=true;
  if(strstr( $argv[$i], '--burp' )) $burp = true;
  if(strstr( $argv[$i], '--only-vhost' )) $onlyVhost = true;
  if(strstr( $argv[$i], '--size-variation=' )) $sizeVariation = explode('=',$argv[$i])[1];
}

if($ports == '' and ($network == '' or $host == '' )) {
  echo PHP_EOL;
  echo '[!] Missing parameters'.PHP_EOL.PHP_EOL;
  help();
  exit;
}
if($host != ''){
  $port = explode(',',$ports);
  for($i=0;$i<count($port);$i++){
    $result = scanPort($host,$port[$i]);
    if($result === true){
      if(!$onlyVhost) echo '[*] Port '.$port[$i].' is open '.getservbyport($port[$i], 'tcp').PHP_EOL;
      if($domaine != '' ){ //check in cert name
        searchInCert($host,$port[$i],$domaine,$checkVhost,$verbose,$sizeVariation,$burp,$onlyVhost);
      }
    }elseif($verbose)  echo '[X] Port '.$port[$i].' is closed (host: '.$host.') '.getservbyport($port[$i], 'tcp').PHP_EOL;
  }
} elseif ($subnet != ''){
  $plage = cidrconv($subnet);
  $plage_begin = $plage[0];
  $plage_end = $plage[1];
  while(ip2long($plage_begin)<ip2long($plage_end)){
    
    //increment de l\'ip
   $ip = explode('.',$plage_begin);
    if($ip[3]<255){
      $ip[3]++;
    }elseif($ip[2]<255){
      $ip[2]++;
      $ip[3] = 0;
    }elseif($ip[1]<255){
      $ip[1]++;
      $ip[3] = $ip[2] = 0;
    }elseif($ip[0]<255){
      $ip[0]++;
      $ip[3] = $ip[2]  = $ip[1] = 0;
    }else{
      echo '[X] error on increment: '.implode('.',$ip);
      break;
    }
    $plage_begin = implode('.',$ip); 

    $port = explode(',',$ports);
    for($i=0;$i<count($port);$i++){
      $result = scanPort($plage_begin,$port[$i]);
      if($result === true){
        if(!$onlyVhost) echo '[*] Port '.$port[$i].' is open '.getservbyport($port[$i], 'tcp').' on ip '.$plage_begin.PHP_EOL;
        if($domaine != '' ){ //check in cert name
            searchInCert($plage_begin,$port[$i],$domaine,$checkVhost,$verbose,$sizeVariation,$burp,$onlyVhost);
        }
      } elseif($verbose) echo '[X] Port '.$port[$i].' is closed (host: '.$plage_begin.') '.getservbyport($port[$i], 'tcp').PHP_EOL;
    }
  }
}
exit;



function scanPort($host,$port){
  $connection = @fsockopen($host, $port, $errno, $errstr, 2);
  if (is_resource($connection)) return true;
  else return false;
}

function searchInCert($ip,$port,$searchHost,$checkVhost,$verbose,$sizeVariation,$burp,$onlyVhost){
  $sizeListe = array();
  if(!is_array($searchHost)) $hostList[] = $searchHost;
  else $hostList = $searchHost;
  $get = stream_context_create(array("ssl" => array("capture_peer_cert" => TRUE,'verify_peer' => false,'verify_peer_name' => false)));
  $read = stream_socket_client("ssl://".$ip.":".$port, $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get);
  $cert = stream_context_get_params($read);
  $certinfo = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);
  if(isset($certinfo['extensions']['subjectAltName'])){
    $allName = str_replace('DNS:','',$certinfo['extensions']['subjectAltName']);
    $allName = explode(', ',$allName);
    for($i=0;$i<count($allName);$i++){
      $tempVar = '/'.str_replace('.','\\.',$allName[$i]).'/';
      $tempVar = str_replace('*','.*',$tempVar);
      for($j=0;$j<count($hostList);$j++){
        if(preg_match($tempVar,$hostList[$j])){
          if(!$onlyVhost) echo '[*] '.$hostList[$j].' (host:'.$ip.':'.$port.') match with domain in cert : '.$allName[$i]. PHP_EOL;
          if($checkVhost){
            $result = vhostRequest($hostList[$j],$ip,$port,$burp);
            if($result[0]!='200' and $verbose){
              if(!$onlyVhost) echo "[!] check vhost return code".$result[0]." vhost :".$hostList[$j]." answer size: ".$result[1].PHP_EOL;
            } elseif($result[0]=='200' ) {
              if(!$onlyVhost) echo "[*] check vhost return code ".$result[0]." vhost :".$hostList[$j]." answer size: ".$result[1].PHP_EOL;
            }
            if(count($sizeListe)>0){
              if($result[1]> (min($sizeListe)+$sizeVariation)){
                echo '[*] a variation has been detect ('.($result[1]-min($sizeListe)).') the domain '.$hostList[$j].' propably vhost of http://'.$ip.':'.$port.PHP_EOL;
              }
            }
            $sizeListe[] = $result[1];
          }
        }
      }

    }
  }
}

function help(){
  echo '--ports           Ports to scan if there are many port separate it by , : --ports=80,443'.PHP_EOL;
  echo '--host            Host to scan (single value) : google.fr'.PHP_EOL;
  echo '--network         Network to scan exemple : 10.0.0.0/8'.PHP_EOL.PHP_EOL;
  echo '--check-name      Only on HTTPS check if certs match with this domaine'.PHP_EOL; 
  echo '--check-name-file Only on HTTPS check if certs match with domaines in file'.PHP_EOL; 
  echo '--check-vhost     if domaine match with the certificate the script try to detect vhost. Require check-name or check-file-name option'.PHP_EOL.PHP_EOL; 
  echo '--size-variation  Use it for detect vhost with variation of lenght response (default: 100) : --size-variatoion=200'.PHP_EOL.PHP_EOL;
  echo '--verbose         Display error'.PHP_EOL.PHP_EOL; 
  echo '--burp            Send to burp proxy request for discover vhost (127.0.0.1:8080)'.PHP_EOL.PHP_EOL; 
  echo '--only-vhost      Show only potential vhost'.PHP_EOL.PHP_EOL; 
  echo 'Only --host or --network not both '.PHP_EOL;
}

function cidrconv($net) {
  $start = strtok($net,"/");
  $n = 3 - substr_count($net, ".");
  if ($n > 0)
  {
      for ($i = $n;$i > 0; $i--)
          $start .= ".0";
  }
  $bits1 = str_pad(decbin(ip2long($start)), 32, "0", STR_PAD_LEFT);
  $net = (1 << (32 - substr(strstr($net, "/"), 1))) - 1;
  $bits2 = str_pad(decbin($net), 32, "0", STR_PAD_LEFT);
  $final = "";
  for ($i = 0; $i < 32; $i++)
  {
      if ($bits1[$i] == $bits2[$i]) $final .= $bits1[$i];
      if ($bits1[$i] == 1 and $bits2[$i] == 0) $final .= $bits1[$i];
      if ($bits1[$i] == 0 and $bits2[$i] == 1) $final .= $bits2[$i];
  }
  return array($start, long2ip(bindec($final)));
}


function vhostRequest($domaine,$ip,$port,$burp){
  $ch = curl_init('https://'.$ip.':'.$port);
  if($burp){
    curl_setopt($ch, CURLOPT_PROXY, '127.0.0.1:8080');
  }
  curl_setopt($ch, CURLOPT_HTTPHEADER, array('Host: '.$domaine));
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
  curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
  curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
  curl_exec($ch);
  $http_code = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
  $size = curl_getinfo($ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD);
  return array($http_code,$size);
}
