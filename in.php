<?php

include './egts_code.php';
include './utils.php';



$socket = stream_socket_server('tcp://0.0.0.0:5569', $errno, $errstr);
stream_set_blocking($socket, 0);
$base = event_base_new();
$event = event_new();
event_set($event, $socket, EV_READ | EV_PERSIST, 'ev_accept', $base);
event_base_set($event, $base);
event_add($event);
event_base_loop($base);

$GLOBALS['connections'] = array();
$GLOBALS['buffers'] = array();
$num = 0;

function ev_accept($socket, $flag, $base) {
	static $id = 0;

	$connection = stream_socket_accept($socket);
	stream_set_blocking($connection, 0);

	$id += 1;

	$buffer = event_buffer_new($connection, 'ev_read', NULL, 'ev_error', $id);
	event_buffer_base_set($buffer, $base);
	event_buffer_timeout_set($buffer, 30, 30);
	event_buffer_watermark_set($buffer, EV_READ, 0, 0xffffff);
	event_buffer_priority_set($buffer, 10);
	event_buffer_enable($buffer, EV_READ | EV_PERSIST);

// we need to save both buffer and connection outside
	$GLOBALS['connections'][$id] = $connection;
	$GLOBALS['buffers'][$id] = $buffer;
}

function ev_error($buffer, $error, $id) {
	event_buffer_disable($GLOBALS['buffers'][$id], EV_READ | EV_WRITE);
	event_buffer_free($GLOBALS['buffers'][$id]);
	fclose($GLOBALS['connections'][$id]);
	unset($GLOBALS['buffers'][$id], $GLOBALS['connections'][$id]);
}

function ev_read($buffer, $id) {
	while ($read = event_buffer_read($buffer, 65536)) {
		parse_data($read, $id);
	}
}

function parse_data($data, $id) {
	global $buffer;

	echo "\r\n\r\nGET PACKET!";
	$packet = parse_packet_header($data);

	if (!is_array($packet) and $packet > 0) {

		logging("terminal_decode[egts]: ERROR $packet\n");
		//вернуть ответ
		response_error($packet, $id);
		return;
	}


	if ($packet['TransportHeader']['PT'] == EGTS_PT_APPDATA)
		parse_app($packet['Packet']['SFRD'], $id, $packet['TransportHeader']['PID']);
}

function parse_packet_header($data) {
	$TransportHeader = '';
	$Packet = '';

	$TransportHeader = unpack("CPRV/CSKID/CFLAFS/CHL/CHE/vFDL/vPID/CPT", $data);

	$TransportHeader['PRF'] = ($TransportHeader['FLAFS'] >> 6) & 3;
	$TransportHeader['RTE'] = ($TransportHeader['FLAFS'] >> 5) & 1;
	$TransportHeader['ENA'] = ($TransportHeader['FLAFS'] >> 3) & 3;
	$TransportHeader['CMP'] = ($TransportHeader['FLAFS'] >> 2) & 1;
	$TransportHeader['PR'] = ($TransportHeader['FLAFS'] >> 0) & 3;


	if ($TransportHeader['PRV'] != 1 or ( $TransportHeader['PRF'] & 192)) {
		logging("parse_packet_header[egts]: EGTS_PC_UNS_PROTOCOL error\n");
		return EGTS_PC_UNS_PROTOCOL;
	}

	if ($TransportHeader['HL'] != 11 and $TransportHeader['HL'] != 16) {
		logging("parse_packet_header[egts]: EGTS_PC_INC_HEADERFORM error\n");
		return EGTS_PC_INC_HEADERFORM;
	}

	$format = "a" . ($TransportHeader['HL'] - 1) . "header/CHCS";
	$Header = unpack($format, $data);

	if ($Header['HCS'] != crc8($Header['header'])) {
		logging("parse_packet_header[egts]: EGTS_PC_INC_HEADERFORM error\n");
		return EGTS_PC_INC_HEADERFORM;
	}

	if (!$TransportHeader['FDL']) {
		return EGTS_PC_OK;
	}

	if ($TransportHeader['RTE']) {
		//Route  у нас не должно быть
		//$TransportHeader = unpack("CPRV/CSKID/CFLAFS/CHL/CHE/vFDL/vPID/CPT/vPRA/vRCA/CTTL", $data);
	}


	$format = "a" . ($TransportHeader['HL']) . "header/A" . ($TransportHeader['FDL']) . "SFRD/vSFRCS";
	$Packet = unpack($format, $data);


	if ($Packet['SFRCS'] != crc16($Packet['SFRD'])) {
		logging("parse_packet_header[egts]: EGTS_PC_DATACRC_ERROR  error\n");
		echo "\r\nEGTS_PC_DATACRC_ERROR {$Packet['SFRCS']} != " . crc16($Packet['SFRD']) . "\r\n";
	}

	$ret = array(
		'TransportHeader' => $TransportHeader,
		'Packet' => $Packet,
	);
	vdx($ret);
	return $ret;
}

function parse_app($d, $id, $PID) {

	/*
	  RL (Record Length)		M	USHORT	2 RD
	  RN (Record Number)		M	USHORT	2
	  RFL (Record Flags)		M	BYTE	1	 * 	  SSOD RSOD RPP TMFE EVFE OBFE	 *
	  OID (Object Identifier)	O	UINT	4
	  EVID (Event Identifier)	O	UINT	4
	  TM (Time)					O	UINT	4   отправител€ (секунды с 00:00:00 01.01.2010 UTC).
	  SST (Source Service Type)	M	BYTE	1
	  RST (Recipient Serv Type)	M	BYTE	1
	  RD (Record Data)			M	BINARY	3Е 65498
	 */

	$length_app = strlen($d);

	while ($length_app > 4) {
		$app = unpack("vRL/vRN/CRFL", $d);

		$RFL['SSOD'] = ($app['RFL'] >> 7) & 1;
		$RFL['RSOD'] = ($app['RFL'] >> 6) & 1;
		$RFL['GRP'] = ($app['RFL'] >> 5) & 1;
		$RFL['RPP'] = ($app['RFL'] >> 3) & 3;
		$RFL['TMFE'] = ($app['RFL'] >> 2) & 1;
		$RFL['EVFE'] = ($app['RFL'] >> 1) & 1;
		$RFL['OBFE'] = ($app['RFL'] >> 0) & 1;

		$app = unpack("vRL/vRN/CRFL"
			. ($RFL['OBFE'] ? "/VOID" : "")
			. ($RFL['EVFE'] ? "/VEVID" : "")
			. ($RFL['TMFE'] ? "/VTM" : "")
			. "/CSST/CRST/A" . $app["RL"] . "RD/A*app2"
			, $d);


		$d = $app['app2'];
		$length_app = strlen($d);
		parse_sab_app($app['RD'], $id, $PID, $app['RN']);
	}
}

function parse_sab_app($rd, $id, $PID, $RN) {

	$length_sub_app = strlen($rd);

	while ($length_sub_app > 3) {

		$sub_app = unpack("CSRT/vSRL", $rd);
		$sub_app = unpack("CSRT/vSRL/A" . $sub_app['SRL'] . "SRD/A*sub_app2", $rd);

		if ($sub_app['SRT'] == EGTS_SR_TERM_IDENTITY) {

			echo 'EGTS_SR_TERM_IDENTITY';

			$SRD = unpack("VTID/CFLG", $sub_app['SRD']);
			$RFL['MNE'] = ($SRD['FLG'] >> 7) & 1;
			$RFL['BSE'] = ($SRD['FLG'] >> 6) & 1;
			$RFL['NIDE'] = ($SRD['FLG'] >> 5) & 1;
			$RFL['SSRA'] = ($SRD['FLG'] >> 4) & 1;
			$RFL['LNGCE'] = ($SRD['FLG'] >> 3) & 1;
			$RFL['IMSIE'] = ($SRD['FLG'] >> 2) & 1;
			$RFL['IMEIE'] = ($SRD['FLG'] >> 1) & 1;
			$RFL['HDIDE'] = ($SRD['FLG'] >> 0) & 1;
			$SRD = unpack("VTID/CFLG"
				. ($RFL['HDIDE'] ? "/vHDID" : "")
				. ($RFL['IMEIE'] ? "/A15IMEI" : "")
				. ($RFL['IMSIE'] ? "/A16IMSI" : "")
				. ($RFL['LNGCE'] ? "/A3LNGC" : "")
				. ($RFL['NIDE'] ? "/A3NID" : "")
				. ($RFL['BSE'] ? "/vBS" : "")
				. ($RFL['MNE'] ? "/A15MSISDN" : "")
				, $sub_app['SRD']);


			response_auth(0, $id, $PID, $RN);
		}


		if ($sub_app['SRT'] == EGTS_SR_POS_DATA) {

			echo 'EGTS_SR_POS_DATA';

			$SRD = unpack("VNTM/VLAT/VLONG/CFLG/vSPD/CDIR/A3ODM/CDIN/vHDOP/CSAT/CSRC", $sub_app['SRD']);

			$RFL['ALTE'] = ($SRD['FLG'] >> 7) & 1;
			$RFL['LOHS'] = ($SRD['FLG'] >> 6) & 1;
			$RFL['LAHS'] = ($SRD['FLG'] >> 5) & 1;
			$RFL['MV'] = ($SRD['FLG'] >> 4) & 1;
			$RFL['BB'] = ($SRD['FLG'] >> 3) & 1;
			$RFL['CS'] = ($SRD['FLG'] >> 2) & 1;
			$RFL['FIX'] = ($SRD['FLG'] >> 1) & 1;
			$RFL['VLD'] = ($SRD['FLG'] >> 0) & 1;

			$date_nav = $SRD['NTM'] + UTS2010;
			$lat = $SRD['LAT'] / 0xFFFFFFFF * 90;
			if ($RFL['LAHS'])
				$lat *= -1;

			$long = $SRD['LONG'] / 0xFFFFFFFF * 180;
			if ($RFL['LOHS'] )
				$long *= -1;
			echo "$date_nav $long $lat";
		}

		$rd = $sub_app['sub_app2'];

		$length_sub_app = $length_sub_app - strlen($sub_app['SRD']) - 3;
	}
}

function response_error($code, $id) {
	global $num;
	$answer = chr(1) . chr(0) . chr(0) . chr(11) . chr(0) . pack('v', 3) . pack('v', $num) . chr(0);
	$answer = $answer . chr(crc8($answer));

	$answer .= pack('v', 1) . chr($code) . pack("v", (crc16(pack('v', 1) . chr($code))));

	//vdx($answer);
	event_buffer_write($GLOBALS['buffers'][$id], $answer);
	$num++;
}

function response_auth($code, $id, $PID, $RN) {
	global $num;

	$answer = chr(1) . chr(0) . chr(0) . chr(11) . chr(0) . pack('v', 16) . pack('v', $num) . chr(0);
	$answer = $answer . chr(crc8($answer));

	$sfrd = pack('v', $PID) . chr(0) . pack('v', 6) . pack('v', $num) . chr(0) . chr(2) . chr(2) . chr(0) . pack('v', 3) . pack('v', $RN) . chr(0);
	$answer .= $sfrd . pack("v", crc16($sfrd));

	//echo ">>>"; vdx($answer);echo "<<<";
	event_buffer_write($GLOBALS['buffers'][$id], $answer);
	$num++;
}

?>