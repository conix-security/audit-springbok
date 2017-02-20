(
	:auth ()
	:crypt ()
	:logic ()
	:proxy ()
	:rules (
		: (rule-1
			:AdminInfo (
				:chkpf_uid ("{22041C72-D02A-48F7-8028-0D6635381740}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{CAAFD3CF-D87C-4B97-BBDA-01C74E616003}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{994550DA-1910-40EF-B456-A24DB4468F4B}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Fwent1
				: Fwent2
				: Fwent
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{B02ACFA5-C148-4269-98BC-E06A873202A4}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{C9F09F3A-09EF-4C76-A541-9051D3831461}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: traceroute
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{0C6EABAB-936C-4AD1-82F2-8831DFDA96F9}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: RtAgence
				: SwAgence
			)
		)
		: (rule-2
			:AdminInfo (
				:chkpf_uid ("{1B2CDA70-1382-4C7E-A112-30073AE98488}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{44DB2367-E938-445E-987F-5F3F974F555C}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{D6542203-6AF8-4AF3-BE3D-BD852DFA3ECF}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: proxent1
				: Net_Pase_relais_entreprise
				: VLAN_DMZ_Serv_Appli
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{5B24CB20-7152-4DEC-A1F4-1B78EC8D64E1}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{16FBC7FA-7714-473E-BF0C-3DBD31DC5F75}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: traceroute
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{BDBCBA39-4396-4700-825F-A1C63756467B}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Fwent
			)
		)
		: (rule-3
			:AdminInfo (
				:chkpf_uid ("{111827A6-23E4-40DA-99C9-916F52668254}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{AFE9CE4B-B816-4365-8AE3-40C8E77E2606}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{D1EC604B-50B0-4612-93E5-7D44D3031662}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Fwent
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{EC0E88FF-C4B8-48E9-97E1-081E62B0C6B7}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{EA3CBF25-B0D3-4C4C-816C-8FA590B5C00E}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: traceroute
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{8EB16762-CFA9-4263-A217-EF6365E194BC}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_Pase_relais_entreprise
				: VLAN_DMZ_Serv_Appli
			)
		)
		: (rule-4
			:AdminInfo (
				:chkpf_uid ("{AD5E0E72-9962-4C1F-A2D0-AB0312F901B0}")
				:ClassName (security_rule)
			)
			:action (
				: (drop
					:AdminInfo (
						:chkpf_uid ("{78CBF471-AACE-4C79-AE72-3BE6627BAF95}")
						:ClassName (drop_action)
						:table (setup)
					)
					:action ()
					:macro ()
					:type (drop)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{4CE33E5B-BAAC-4C3F-BC46-4F9521DF05CD}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Gr_remote_hosts_suspects
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{52B46247-B212-46B6-B4A9-DECA9ECFBFD4}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{DEC0FF90-5863-4244-B994-2E4397991A00}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{D0EABC0B-CA68-4CC6-8513-2020CA4EE4F3}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-5
			:AdminInfo (
				:chkpf_uid ("{995E12F5-5297-477E-944C-2B32A4FF6D62}")
				:ClassName (security_rule)
			)
			:action (
				: (drop
					:AdminInfo (
						:chkpf_uid ("{6DC07FDD-1C5B-43AF-A2CB-956DDC57E0AC}")
						:ClassName (drop_action)
						:table (setup)
					)
					:action ()
					:macro ()
					:type (drop)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{29528F63-8851-44EE-95E9-3F4DA069EFAE}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{089A2738-EF31-4911-A6DF-77C1508BA026}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{79A9E9F5-2A55-45B4-A3B8-42BEFEF61A7E}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{B47651D2-A15F-448E-A937-D59CED05B188}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Gr_remote_hosts_suspects
			)
		)
		: (rule-6
			:AdminInfo (
				:chkpf_uid ("{2B34BD18-0BEE-4913-A2FA-728288681399}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{19A4FA68-96F2-4524-AF4B-1A170327F284}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{FEB95069-A16A-4342-8756-7CC4E20A5B42}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Net_Multicast_VRRP
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{42918681-FEEB-43FF-8B38-4266C3C2300A}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{9D5EF54E-0375-462A-AE11-D805278909D0}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{C5119FE9-32DC-41CC-9F7F-26EC5EC49EE9}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Fwent1
				: Fwent2
				: Fwent
			)
		)
		: (rule-7
			:AdminInfo (
				:chkpf_uid ("{2E882C69-270A-4DB3-9646-8A7098F78038}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{2DDEE942-9DE1-4DFA-82E7-8EA73803F5EE}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{3A2F439C-CCE5-4535-AE94-0960678161C2}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Mail_Exchange
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{A6A6C0F2-7E8D-4EFE-B94C-A3D9E7D76874}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{B1BC51EF-BFD0-4A90-A9BA-97A04AE3321D}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: smtp
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{4A2FC8C8-78BB-4B83-8D93-8EA5350A5642}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Fwent1
				: Fwent2
				: Fwent
			)
		)
		: (rule-8
			:AdminInfo (
				:chkpf_uid ("{4C209B54-DCF4-4791-905E-FBA328FD00A2}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{6D423FCE-285E-40F8-AB97-62D465D6F6D4}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{DA3ACCBE-D262-4DCF-936D-A1B8BC56EA52}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Fwent1
				: Fwent2
				: Fwent
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{BEB574CE-48BD-41E5-BA90-A9F96EC7BE32}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{AD1ACB7D-8116-443C-BA7E-8DCE4012C651}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{8563104C-C057-42AE-9CEB-04832420D04A}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_Multicast_VRRP
			)
		)
		: (rule-9
			:AdminInfo (
				:chkpf_uid ("{88E618CE-18FE-4120-9573-28C9033C372F}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{4CCF1311-C569-41A6-8CF2-E1FBAC41D88D}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{722B7E3D-D7EF-4329-A0E0-54CECAC3B613}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Fwent
				: Fwent1
				: Fwent2
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{795B28BC-5755-47D8-957F-142E530586E7}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{CEFB5BB0-AE2F-49FA-930C-CB4A740AE5B4}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: FW1_topo
				: FW1_pslogon_NG
				: FW1_scv_keep_alive
				: FW1_sds_logon_NG
				: tunnel_test
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{8B64D654-F802-4D12-9CE7-2C3BB24D4248}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Adresses_Publiques
			)
		)
		: (rule-10
			:AdminInfo (
				:chkpf_uid ("{9CEE3E03-E3C6-4E12-94D8-AB3A5F71121B}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{83D2A79C-27AE-4B36-B751-B4FBA37F2DAD}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{EEBD5F5C-A574-4F3B-9A2A-E6A91BC2FB3B}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{22E0D908-F2D3-4604-A58F-317B05FBDC84}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{9F689600-7C39-47C0-A6C2-FD1F5AC50C56}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: pop-3
				: smtp
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{4116AA62-202D-4CC2-9F72-9392646CC442}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ADMIN
			)
		)
		: (rule-11
			:AdminInfo (
				:chkpf_uid ("{96459387-155A-482E-ABE5-56362CC1CA8A}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{0F2FDBBA-32CB-4A46-A201-C6255C17CE8E}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{F40F7288-593E-4ECA-AA95-353214030392}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: VLAN_DMZ_Serv_Appli
				: Net_Network_Pase_Entr
				: Net_Pase_relais_entreprise
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{09CF916C-9537-429F-9A55-9E44C9057665}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{54E36CEC-F14F-42F7-8F69-7C1354DDBE5B}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: TACACS
				: TACACSplus
				: traceroute
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{D676024B-6F1C-46E5-A813-5CE030AD93F1}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ACS_Interne
			)
		)
		: (rule-12
			:AdminInfo (
				:chkpf_uid ("{72E41023-E257-4E8C-9807-B2EBC8B33D0B}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{CD29B504-029C-49B4-8C15-AEDF8DD142E4}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{F7B231B9-AF15-4E91-97E7-848EAB1DFB46}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{D8DD8235-41C7-4EAD-888F-A096D7533526}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{3341F6C6-2ACB-4599-AD7C-F60B64C5CBC1}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: telnet
				: ssh
				: snmp
				: snmp-read
				: dns
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{33EB35E6-25AD-4FF5-A207-B3944FE59B17}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Smokeping-interne
				: Srv_New_NTPINTERNE
			)
		)
		: (rule-13
			:AdminInfo (
				:chkpf_uid ("{DC71F249-5EB6-4A1B-9DE4-D5F6EAC836E4}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{224EEA29-CA7D-47D7-8DBC-390B06286086}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{E4AC553C-2A26-42BE-A3C1-91A1351CE8FE}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{183BA083-0E08-4DFB-86C7-9707A258B4AF}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{9633E1A0-3169-48FD-8BC0-A9B602E57237}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: snmp-read
				: snmp
				: echo
				: NRPE
				: traceroute
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{3E9637D2-C813-4435-937B-CFD4297A7403}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: G_supervision_snmp
			)
		)
		: (rule-14
			:AdminInfo (
				:chkpf_uid ("{591F6313-413C-4036-AF14-347B49553F9B}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{13C09D87-76E3-4A16-9222-1E3C666C25BF}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{3D9C898A-6664-402C-9B46-CA57AC73B7B8}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{BBB12655-B2C3-411D-B2BA-F358E80926D2}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{C7F000EA-1AFE-41AB-89D9-30331DC8C031}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{65B366E5-F1E4-4B3F-88C3-E86E5FFBEC72}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: srv_net_NetFlow
			)
		)
		: (rule-15
			:AdminInfo (
				:chkpf_uid ("{C95C26AC-4E5C-4207-8C8E-89F79E2EAC59}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{D56CF7FF-3C22-4A76-B89D-872E9905EFE3}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{420B187D-632D-4BF6-B2EA-EA33DC2FBC6D}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: ACS_Interne
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{401E2D02-5225-4267-81BF-90652B152005}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{1CF79120-C6B0-41FD-A59F-2542FED2B80A}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: TACACS
				: TACACSplus
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{B6034B50-0F77-435D-8E5C-EE323CF39061}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_Agences_Minilink
				: RtAgence
				: swent1
				: swext1
				: swserv1
			)
		)
		: (rule-17
			:AdminInfo (
				:chkpf_uid ("{F81C3758-18D2-47FC-B0B5-A1B4CA3D374F}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{09F5CC65-D215-4D33-B5A0-543FE6DB9A9E}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{FF48E510-44EC-4DB8-BD6F-E42E862CBBA5}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Fwent1
				: Fwent2
				: swent1
				: swent2
				: Fwent
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{FFD572CD-BA29-4C5E-98FB-85BA9236989C}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{5F8DB159-32D8-463D-8729-F9F0B97EF9FD}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: telnet
				: ssh
				: ssh_version_2
				: http
				: https
				: traceroute
				: snmp
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{57BE5EAF-4646-4504-B2F3-287CBC0B7385}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: SI_SAdmin
				: ntpi1interne
			)
		)
		: (rule-18
			:AdminInfo (
				:chkpf_uid ("{DD2392F5-434E-481A-8D39-185367E44234}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{2BBA3C6F-358A-4309-A564-BBAA07622483}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{0EC66D7D-75C9-434E-B09D-45D36D31E493}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: DSI_DIO
				: SI_Admin
				: SI_SAdmin
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{9577267E-EA92-4A31-879C-544BE22BBB87}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{9E2DF72D-75AD-4241-A64F-D0B9BC722340}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: ftp
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{F2985CBC-F20F-4A3B-9792-F27DFEB69AED}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: proxent1
				: fwmgr
			)
		)
		: (rule-19
			:AdminInfo (
				:chkpf_uid ("{842F0677-1A03-4BB5-BA91-3A7050484E91}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{29A0A7C3-74FC-4882-AA90-C2BDE2517BCF}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{E770843C-889F-4A1E-B382-941EA28DDB65}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: SI_SAdmin
				: DSI_sadm_BZR
				: ntpi1interne
				: srv_net_NetFlow
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{351D4ECE-6795-4EDC-B67C-B151FAF0FE44}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{D991402B-03A9-4F15-A4AE-1193ED0DE66B}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: echo-request
				: traceroute
				: tftp
				: ntp
				: NetFlow
				: snmp-trap
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{E3D18675-35FE-42C4-B9CE-1BD15F8D2521}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: rtext1
				: swent1
				: RtRelaisRemotes
				: swext1
				: swserv1
				: RTinValide
			)
		)
		: (rule-20
			:AdminInfo (
				:chkpf_uid ("{B84F2F39-F683-4B1C-BAEF-1B14C3B70313}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{5ED56C8B-5BE5-42B8-8085-043EA83B74ED}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{0CCF7CFA-3586-416E-B362-9957CD61B8B6}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Net_equipment_IPro
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{D626736F-A1E2-4EC2-AE08-B10A7D342F04}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{1A767AC3-0656-4C1B-BD72-A3CCB4082576}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{11A2F3FA-B2CA-40EE-A2C7-9F1D0B1F2C7C}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: G_supervision_snmp
				: SI_SAdmin
			)
		)
		: (rule-21
			:AdminInfo (
				:chkpf_uid ("{049DFAF4-CB96-4880-A71F-D03C82E53275}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{00AE70B1-6C69-41A4-A4CB-6C0660193D82}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{DC3B5C0C-C20C-4D90-9786-C0A971D84552}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Net_ISP-NOC
				: Net_New_ISP_NOC
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{DF9EEBEA-EB78-4ED0-B2FF-D90D08A9FBD9}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{9EFA945F-66B8-4EA5-990F-833966A06BEA}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http
				: https
				: icmp-proto
				: traceroute
				: tcp_8181
				: https_1741
				: http_proxy
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{DDA4FB01-0C55-4734-AD56-35AFDC1C553D}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Pc_Super_Entreprise_1
				: G_Access_SE
				: G_Superv_MSC2
				: Pc_Super_Entreprise_2
				: Pc_Super_Entreprise_3
			)
		)
		: (rule-22
			:AdminInfo (
				:chkpf_uid ("{04F95F2B-B4B1-4CE5-8DCC-52DBCDB5FDD3}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{B21968AE-0C7B-48DF-AA46-E031AA558685}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{ACD19DAD-8E4C-4D99-A52E-25AFA37A7944}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: srv_OBS
				: Srv_Ancien_Smokeping
				: Smokeping_test_telma
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{D98A8F92-3346-486F-8238-3CB2F064629B}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{FBE48CDF-027F-470A-9992-E54C6553CE0F}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: ssh
				: ftp
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{AC4E4627-DE40-49C3-B2CB-FF54D05FB21F}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: SI_SAdmin
				: SI_Admin_1
				: SE_Admin
			)
		)
		: (rule-23
			:AdminInfo (
				:chkpf_uid ("{D6BC01B7-C06D-41A8-8F1F-8CC375ED4F72}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{840BAB81-1E54-4811-944B-C9F0AAEEAB45}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{268CD739-2091-4E82-9955-0F7E928DBEA1}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Srv_test_vpn
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{131D4AA3-D33F-4201-A2BE-58AC227F0428}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{581A34C1-1F52-43B6-ABC6-B3B5E502F6B1}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: traceroute
				: microsoft-rdp
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{A676505C-F039-453F-9DB8-18AD048C31BF}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: SI_SAdmin
			)
		)
		: (rule-24
			:AdminInfo (
				:chkpf_uid ("{46DAB6D9-46FC-4AB7-B878-28FA7FE4DA8D}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{24B5A7A1-987A-4ED0-BB52-AB18732DA7A9}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{B79BFAC1-6721-4E81-93BD-87A85453EFA8}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: fw_asa_5540
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{88D08959-5A88-422E-86EA-19FEF53FA94C}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{92DA96E2-E802-4CB2-80BE-7131CDB5FCDF}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: traceroute
				: https
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{C9C56B7A-D1C0-4D8F-9006-B52B282ACCB1}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: SI_SAdmin
			)
		)
		: (rule-25
			:AdminInfo (
				:chkpf_uid ("{FBF8EAD4-7744-4C04-85A0-69ADB78C97BA}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{794BD7E4-3ED4-4DB5-A155-EDF26AB930EB}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{F87686F5-8D12-4A16-A998-163E649CB55D}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: srv_OBS
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{5FCB9469-FE5E-40B2-846F-61F0CE0D2497}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{92C1A2CC-C7BA-4EB8-B682-2E3729018F9C}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: http
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{2B496E7D-A944-4012-A6F3-D6F04254043B}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: G_srv_prTech
				: G_Access_SE
			)
		)
		: (rule-26
			:AdminInfo (
				:chkpf_uid ("{9688873F-AF29-4107-82D6-1F7EA2FDF772}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{1DA267F9-FB35-450E-BDE9-39F67AEDFECB}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{5717176F-F973-4B79-A18D-2810160242A6}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Net_New_Noc_ISP
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{4E0497C9-64EF-469D-88E5-7AD84DF7A372}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{8EB284CA-B501-482B-B601-3DF911313E33}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{F4B6C38B-9C1B-4320-9FD4-370A00D7D469}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
			)
		)
		: (rule-27
			:AdminInfo (
				:chkpf_uid ("{4B10B95A-1CC0-4334-9615-2A4AE9DF8648}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{FE723607-8661-4253-9A69-BCCC76EECAC0}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{379E2E10-4075-44A4-A2E8-AA93257E7D06}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Net_NOC_IPNGN
				: Net_41.190.238
				: Net_ISP-NOC
				: Net_New_ISP_NOC
				: srv_noc_bmoi
				: IP_41.63.159.250
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{8FA5B16B-021A-41EA-9BC7-7C467E3BBC86}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{3521DC79-D39A-4A4E-A44F-66BC21BB4EC8}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{71D6F63B-81C0-4E85-89B6-9710836784F7}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: SI_SAdmin
				: SI_Admin_1
			)
		)
		: (rule-28
			:AdminInfo (
				:chkpf_uid ("{38DC978A-AB1F-4ECB-BD17-81272FBBB773}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{EC515861-5DD0-433F-9622-1C0E4E1BFE9E}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{798A290D-7DC8-42BF-830F-334A1B3FA658}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{FEDDF2EA-9EF9-4AC3-8FAA-328A98FC12E2}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{8C29C680-27E1-4EE1-AF6B-030D06B96BDA}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{DC344ED3-5258-43CF-A81C-CFDAD8B504A5}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Srv_Sniffer_Wireshark
			)
		)
		: (rule-30
			:AdminInfo (
				:chkpf_uid ("{2330ABCF-EEED-4B71-8EC5-A3DC878186E0}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{7677A25F-4FF2-4F22-A6EF-1C18414B67A6}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{C23CCFD4-F24E-437D-9211-26D13EEA6C1A}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Gr_Subnet_Skill_Soft
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{186600A6-02DC-4D08-973C-2688DAB662CC}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{1CA9B762-ED80-4328-B98D-376CF07C1B3E}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
				: http
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{E6D16F10-630F-4495-BFB3-2D420CB9846A}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
			)
		)
		: (rule-31
			:AdminInfo (
				:chkpf_uid ("{8C55378E-4D96-48C3-9189-3181F5673CB2}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{81E9E79D-FD32-45A1-9D24-0319F045F18E}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{3444C69F-6876-4A52-99A7-93E394CD59FE}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: pvsp72pfe.skillport.com
				: library.skillport.com
				: pvsp72pbe.skillport.com
				: innovation.orange.com
				: pvsp73nfe.skillport.com
				: xlibrary.skillport.com
				: pvsp73nbe.skillport.com
				: Srv_Portail_oma_fe2
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{22654BD8-52D6-4CA5-81FC-A17DD5CB6650}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{2BB402F8-BBC6-4EC1-8060-C9675CC3122B}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
				: http
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{63A1D4B5-2A78-4602-8032-2E4616BCBAC4}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
			)
		)
		: (rule-32
			:AdminInfo (
				:chkpf_uid ("{11B11A2A-024E-4AB0-8100-A9E91CAAC494}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{A2AC79AA-FB0B-429B-984B-CACC5F432013}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{F71BE19F-6F05-4E1B-A3EF-34F7927D0E87}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Proxy2pub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{44E414D8-CE47-4C5B-BD75-07E51E6566A5}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{C3D44EDF-0281-41E6-813D-48C546AC0A82}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: traceroute
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{59B308A5-D59C-4616-9206-773B7480365C}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-33
			:AdminInfo (
				:chkpf_uid ("{F0FEAFA8-72C8-44FD-8997-1451EBDC9039}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{9869E927-47C8-4F5C-833B-EE2AA11F85FF}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{B47BC542-F6F4-4B0E-B64B-9A64D5A318F9}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Adresses_Publiques
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{8630DC3F-D60B-434A-BFF2-FC5E19EF823D}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{BA763D7E-AD13-440A-884A-A229B48FAC8A}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http
				: https
				: http_proxy
				: http_444
				: Http_98
				: http_9998
				: icmp-proto
				: traceroute
				: http_450
				: http_8000
				: tcp601x_webradio
				: udp601x_WebRadio
				: tcp-high-ports
				: http_451
				: telnet
				: smtp
				: ftp
				: ssh
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{745ADEA4-91BD-4CF5-97FE-CEC8FFC17534}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ntpi1interne
				: PC_test_supervision
				: srv_test_nagios
				: srv_ftp_local_3g
				: Smokeping-interne
				: Srv_New_NTPINTERNE
			)
		)
		: (rule-34
			:AdminInfo (
				:chkpf_uid ("{88637E75-D33C-4E1E-A6D4-27C407FA9B94}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{5DE1113E-33F4-49A0-A82C-0C15C79D5252}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{2E63E944-A04C-4F7E-BE0C-A073C930B2DA}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Adresses_Publiques
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{D58387F8-4850-4F6B-94AE-B9285FF7E4EA}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{799842FD-88FD-4F33-8D67-8A8323848EAC}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http
				: ftp
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{334E5927-ED71-4745-939F-FF924813F5DA}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: smtpent1
			)
		)
		: (rule-35
			:AdminInfo (
				:chkpf_uid ("{60331E2E-3057-471E-B09A-57FBF5F03BB8}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{CDBA2874-50EB-4D5F-B058-2AECF0475D94}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{E991E68A-860B-4BAE-B347-E6C6CC71B3C8}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebRadioPub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{E63707B7-E824-46CE-BED2-E1499DE8F518}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{4647D814-D909-4595-B7BC-C155F4D7A614}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: X11
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{66283BCB-E6A2-47C0-8ABB-44F093AB9F41}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
			)
		)
		: (rule-36
			:AdminInfo (
				:chkpf_uid ("{F3D21684-A1AC-4075-BC60-ED5635795554}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{24AD0840-F9E9-40A0-BB76-37D3FE03C68A}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{044F734B-A8D1-4A79-A27D-B2C19CDC6C3C}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebRadioPub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{A0832298-F9BE-4C90-AF60-03C9C70A5711}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{16F2E41C-8FB9-48D6-A3C4-A707E54B7A5B}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: tcp601x_webradio
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{D8102EE8-ED8E-4B84-8231-D0D02C61DBA3}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
			)
		)
		: (rule-37
			:AdminInfo (
				:chkpf_uid ("{22D18531-CB7F-4682-BE34-29E3CCF50610}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{6BEA69F8-A8AC-4A1F-AE69-5ACD3492AD9F}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{1BD19CA3-F34E-444D-8B4C-FEA3647C0410}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Adresses_Publiques
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{F7DF58B0-D6ED-495F-B220-7F1E62AAE923}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{76C9C196-4E00-4EF2-BDA7-00C6CB591E98}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: ftp
				: ftp-data
				: traceroute
				: icmp-requests
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{46720F4C-9D18-4ED3-8FE9-3E77818ED622}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ntpi1interne
			)
		)
		: (rule-38
			:AdminInfo (
				:chkpf_uid ("{B458F72A-6E0B-4525-9B2E-95A4A5D506BB}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{F0FEF930-AEBF-44D7-8956-1B765A95B2A1}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{7A0B4700-EB80-45DE-AD89-5B50EA2EEE97}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: G_srv_DNS
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{8576989A-D1C3-4D76-B734-3D8B7F9B345F}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{6D938743-B636-4FA0-AD02-2D09AEED2613}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: dns
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{BC5255BF-1DB1-40D6-88E9-5FF2F8B729A2}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: proxyISA1
				: ProxyISA2
				: ntpi1interne
				: fwmgr
				: srv_test_nagios
				: Smokeping-interne
				: srv_ftp_local_3g
				: Srv_New_NTPINTERNE
				: ProxyReverse
			)
		)
		: (rule-39
			:AdminInfo (
				:chkpf_uid ("{9EF21C86-1DA9-417C-8BC0-7D1363386E98}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{3ACE2CA4-85F0-4593-83CC-F6C8F2570304}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{AE96FE1F-8ECD-4F57-ABAB-6E28C1238443}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Srv_ip_SMTP_pub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{B9C689AA-B8FC-4E2C-8DBE-1F224DD22C72}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{5C5E86C0-B53A-485D-ADA6-6EF1307B570A}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: X11
				: X11-verify
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{9A006D6D-1613-48CA-87E4-2E16EEDBE6E1}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
			)
		)
		: (rule-40
			:AdminInfo (
				:chkpf_uid ("{BCE7D836-B1F0-4BB7-BAF3-B874CA655BB5}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{6B7D99BD-A030-40C4-932B-1097B1AFBCA3}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{0120B0C1-BFA8-47E6-B804-895E6C0C049F}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Srv_ip_SMTP_pub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{2DA3CD42-702E-4C4C-8E15-64E0D586E263}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{9CB1DDE8-329E-4E6F-A190-A89379B34859}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{FC0633BB-9B31-4233-AEBA-BBC97399F244}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
			)
		)
		: (rule-41
			:AdminInfo (
				:chkpf_uid ("{894A8762-B9BA-4BC4-B5F2-8BC25F3B37A7}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{0F9F288C-B9FA-4703-9855-8A8CEC250DDD}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{7B8745D0-A910-4D05-A801-E375D5ECFB1E}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Net_ISP-NOC
				: Net_Noc_BMOI
				: srv_noc_bmoi
				: srv_noc_bmoi_v2
				: Net_New_ISP_NOC
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{1CDAAC7E-F3BC-4EB1-A3D9-244714B98911}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{340D7B20-B107-4279-B8D5-E2405BD9245F}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http
				: https
				: icmp-proto
				: http_proxy_8081
				: tcp_8181
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{0AE83154-FD9C-48E2-8A45-947403DBAB32}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
				: G_Superv_MSC2
			)
		)
		: (rule-42
			:AdminInfo (
				:chkpf_uid ("{0ACCCD1D-ABC0-424B-A1AF-4EF6E67A2D06}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{8C1A1DA6-B0C1-4E83-A58E-A0086468BD87}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{27A9183B-4FD2-4300-9DAD-44511945E90B}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebRadioPub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{296547C2-B4EB-4397-A78C-5F9B430FDC68}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{5372BD2A-729B-4137-A71D-E2A0FAB5FC76}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{15F63047-388C-4B75-AF60-1665E453048C}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
			)
		)
		: (rule-43
			:AdminInfo (
				:chkpf_uid ("{4F6EC508-F700-41F6-AD21-A6723A73ACD7}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{B09CA193-9806-4553-87D4-5E543D65965A}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{0473ACC5-363D-461A-988C-BB3997163CBF}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: PushMail-provisionning
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{4D1A11CE-A65C-49F2-8B83-4C8591F335FD}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{6D6B8C8E-61E1-4C1A-8E34-89F16C9BC022}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http
				: https
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{42465B68-C67A-4BD6-AE26-24D1A27B0DCD}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
			)
		)
		: (rule-44
			:AdminInfo (
				:chkpf_uid ("{650B667C-E904-4ADF-AD16-776DDEFF89AF}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{D91F6858-5922-4CBE-9E09-58398D6D7EAA}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{C371C930-3545-42EC-9E82-FEC26A5AEB0C}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: URL_cdn.webtv.multimediabs.com
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{16FEC1BB-931A-4EE1-AAF7-5E87CEC6908B}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{B18D42CE-24E2-407B-AB61-00DA1BEA5C73}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http
				: https
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{D1D90452-9C34-4C71-BB3B-F89C274C6F3A}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
			)
		)
		: (rule-45
			:AdminInfo (
				:chkpf_uid ("{5C875F38-4B04-4C3C-B5C6-BE8462CFD3AE}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{1ACFF661-EE5A-4132-B52A-B066DA8B4B06}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{678C3D15-0DF2-4905-A49D-6CC54D1F4F1C}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: IP_41.204.120.201_Gasynet
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{58DFD0E5-45E1-4C27-9B41-C6500E7D6393}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{CAA37FF5-86C1-47A4-88AD-5CA935910089}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http
				: https
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{023BC77B-FF81-40AA-8A8B-B00D2C14F7CC}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
			)
		)
		: (rule-46
			:AdminInfo (
				:chkpf_uid ("{9FE4DB32-47BF-4611-890D-BB41F422155D}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{7558CBE2-CA4B-403A-908C-A691C78BD211}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{12C88EE9-E147-4FC1-A41F-FD780336820F}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Srv_Proxy_Rev_27_ISP
				: Srv_Proxy_Rev_30_ISP
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{801B1933-82C6-4119-A658-C272F663B561}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{5A2B0A01-71DE-4F23-9C6B-A0AE55877B3D}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{11D9742E-1D58-421E-B9A0-116CE94E899A}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
			)
		)
		: (rule-47
			:AdminInfo (
				:chkpf_uid ("{B5A4808F-0F41-4C69-B5AF-E06DB26F8A5F}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{CF96C1B0-0AE1-4D52-9A5B-FBD3507CBC5D}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{C16C4B53-34E9-4ADA-9985-6D555300AF43}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Url_savon-oma_blueline
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{50437CB8-2D3B-4BBD-BD01-7A87F1D7BBE3}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{E8709FC7-40C6-44EE-9F9A-BF683D50FEF4}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{C53DF915-1B26-47C6-8C36-53ED514B6C00}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: DSI_SVA_RAB
				: DSI_SVA_SANDRATANA
				: PC_CRM_SOC
				: Srv_Mpanjiva
				: Srv_Mpanjiva_Test_Bed
			)
		)
		: (rule-48
			:AdminInfo (
				:chkpf_uid ("{A0D8DF17-648F-4B04-8F92-2D3DFB6342F5}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{F52665AF-E327-4E2C-BD8B-9F7B04E8C63F}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{E9C0DC78-1392-431C-AAC6-A17327FEDDA0}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Url_savon-oma_blueline
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{64651CDF-7561-421C-805F-EA59BF1417AF}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{860DAB6B-A1D5-4AA2-9435-08A2C57E5AE5}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: ftp
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{3323C262-26B1-4468-945A-5CFA10D8741C}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Srv_Betsiboka
				: DSI_sadm_BZR
			)
		)
		: (rule-49
			:AdminInfo (
				:chkpf_uid ("{009A58D5-B61C-48C7-A2A7-0D0B58C2F9FF}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{039F0627-1DA5-40AE-8672-0CC617FC72FA}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{6B3C47A4-FDB6-40F3-ACBA-6CB6E899C321}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: ftp.volubill.com
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{81E00DD7-1979-4B79-BB7B-685F086F8A41}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{8F14CB8A-AA22-4E70-8688-B953DE6D547C}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{AF4B4A6D-7191-44DC-9454-F876726604D4}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
			)
		)
		: (rule-50
			:AdminInfo (
				:chkpf_uid ("{BF2B9201-DDC6-4F63-A825-71B8F263C080}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{F824ED85-67FE-4FB8-9274-3A730CE8FA4D}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{7BEA7A2C-EA9E-41EB-8F23-C835D192B615}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: srv_ftp_jirama_Orange_Money
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{FA71C5CA-C5C9-40F2-A334-3A48D470B9EF}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{ECAA7D2C-D571-4E45-9B6B-69F9CEB792C9}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: ftp
				: ssh_version_2
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{39094088-5796-4ED6-BB58-F9D764BC6DD0}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: DRH_ERN
				: DCVI_OHA
				: DCVI_ONT
				: DCVI_AML
				: DCVI_RGN
			)
		)
		: (rule-51
			:AdminInfo (
				:chkpf_uid ("{1C844DF7-FFF8-436D-A7A0-B3ADF5D55A6C}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{9D5CD3CF-A620-48E0-9C5C-9492F5F15BCA}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{C51009BB-5BEF-4BC7-BC38-2C30B0FAAF82}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Site_mfsafrica_biz
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{4D01CC89-3E9E-462A-BCBD-21DF7F86600D}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{627740E7-F41A-4A0A-A966-8793FD9D9936}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http
				: https
				: http_proxy
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{7B517CA9-82AA-4FD7-AC78-75437E7F96C7}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: DCVI_OHA
				: DCVI_ONT
				: DSI_SVA_SANDRATANA
				: DSI_SVA_FMR
			)
		)
		: (rule-52
			:AdminInfo (
				:chkpf_uid ("{445809B3-A609-48C3-A4DD-9E5EFD03C687}")
				:ClassName (security_rule)
			)
			:action (
				: (drop
					:AdminInfo (
						:chkpf_uid ("{3724E658-5FBB-40C4-9562-09D3C38EA944}")
						:ClassName (drop_action)
						:table (setup)
					)
					:action ()
					:macro ()
					:type (drop)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{1DF06BE9-65D4-4617-9E12-AC2DC55DE79B}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{C719427B-61C7-492B-AAE0-FD3C43D5244A}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{9ACECCA2-90E9-4D79-956B-5B96189B1A05}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{B7FDF266-A897-473F-88B9-A3B0F946B0B3}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: PC_inconnu
			)
		)
		: (rule-53
			:AdminInfo (
				:chkpf_uid ("{594A34B7-E2F8-4A8A-812E-9CFE5DFDDDCD}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{6BE0DA16-FD24-44D6-B9CD-D71C19D5E521}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{6A979A87-08CC-4A0B-9225-5527FF1FDF3A}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Modem_NewTech_68
				: Modem_NewTech_67
				: Modem_NewTech_66
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{C2FD8EB6-96AC-4CDA-AD52-F9E14028ACAE}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{9ABF139F-FF34-41AB-A625-FF9B52994EC2}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{D25A71AD-6201-436F-83B1-CF28D08E718C}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
			)
		)
		: (rule-54
			:AdminInfo (
				:chkpf_uid ("{0F151CDA-4799-4DE2-AAD3-04D0C5C11957}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{97B32D42-48D0-43C0-A897-305E4D69C428}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{F278DA29-7B3C-4D03-A7A0-CF1AD4E4DCC3}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: pubent1_t
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{6819598D-7379-4388-BA50-01AD77067FB5}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{B07393B2-492C-45B3-B649-15004DB9DB3A}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: smtp
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{618C57DD-287A-4C47-B365-6D7D9D081223}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Adresses_Publiques
			)
		)
		: (rule-55
			:AdminInfo (
				:chkpf_uid ("{6BAE45A7-6DDE-4BDE-990E-09955D945357}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{2AE06731-000F-4144-9532-1EAED924FEC2}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{C252FAF4-F61A-4297-966A-442B2462F82D}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: pubent1_t
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{792CC48D-ECB9-44AE-83D1-5B6BFB4DB51E}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{7BF9B10B-88A7-489E-817D-CCE73D89B875}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: pop-3
				: imap
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{CC616A8E-508D-4650-8195-CB178F73F795}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: G_ext_POP3ers
			)
		)
		: (rule-56
			:AdminInfo (
				:chkpf_uid ("{5C618673-3083-484D-8B5A-6D98C4DDE384}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{6FBF4088-050E-4564-A057-3414C004BFDB}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{54926D05-3AEE-424E-AE7C-321B5C983633}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Remote_pop_orange
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{2FAB297F-D9CD-4E89-9B9F-D6F8B58161A5}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{83ED87E1-EDE4-42D0-9A16-A51ACFA30E1C}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: pop-3
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{4DEEA1AB-A509-4604-B864-2595DD68BE33}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_Clients_23high
				: DMCC_LVL
			)
		)
		: (rule-58
			:AdminInfo (
				:chkpf_uid ("{E2600763-A398-4BED-805F-98BFB5AB771E}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{FFDBBFE4-A7B2-472C-B98E-C37B1304EF22}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{2E5827DE-67C4-4C84-9464-5381AD9602F7}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Srv_Proxy_TMM_Priv
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{39F80E49-C096-45BD-9AB3-1BC41EEF139C}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{0B9A6E64-2A7F-48FD-B6D2-F473FC3BB0A6}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: X11
				: X11-verify
				: udp_177
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{EE654585-9C3B-4705-8833-E00B057AE82F}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: SI_SAdmin
			)
		)
		: (rule-59
			:AdminInfo (
				:chkpf_uid ("{905F85AC-1464-48CE-B437-F0DDB2E359BD}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{4615F43E-FD1A-43D3-B732-D707F2D24073}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{67A1A17A-C9CD-41C7-B397-C4E1204698A0}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Srv_Proxy_TMM_Priv
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{6E0FC707-62A6-4D9B-8B3F-299F2FCB00BC}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{29CD1B05-F989-4544-B1CF-FF68EA0B2A83}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{9E7F0A5D-5894-427A-BDF9-5E5961888785}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: SI_SAdmin
				: SI_Admin
			)
		)
		: (rule-60
			:AdminInfo (
				:chkpf_uid ("{1F25CFB3-FF4B-442C-8797-8798714279CD}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{4B4A3C79-B2BB-4605-9D0B-252081BE3A77}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{169CDE56-714B-43D2-8A19-81F1A4EEE1D2}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: SI_SAdmin
				: SI_Admin
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{32D72B4E-15BC-42D7-B5D8-C436CD4B94C3}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{5DE5F997-75A5-4BAC-9929-4E58D33AA95B}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{5C620522-6B86-4A05-A315-B01391088A97}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Srv_Proxy_TMM_Priv
			)
		)
		: (rule-61
			:AdminInfo (
				:chkpf_uid ("{984FBAF5-35AE-406E-A590-1117EF988BC3}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{F9D229B1-0243-4A63-B4ED-7744D3524069}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{86A88E00-8ABF-4D28-A894-9B063460FED5}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: proxyreverse2_priv
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{74542A44-E90A-4FCE-89AF-9D0F5C68DAC2}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{F1E49396-8B3F-492B-824C-DD9C46CD98F1}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: ssh
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{33662AEF-B30B-4602-9989-EEB7A88380E6}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: DSI_SVA_RAB
				: DSI_SVA_HMB
				: DSI_SVA_SANDRATANA
			)
		)
		: (rule-62
			:AdminInfo (
				:chkpf_uid ("{590835FC-7A70-4BD1-8EF9-2826B67A1310}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{1EF0FFE5-BA3B-4B42-8E6B-22B4A4403034}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{42062C2B-A083-4758-BD3F-B90B9DD1A7D4}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: G_srv_DNS
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{3433C021-6697-4537-90CF-B96AD036EE09}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{D1BD2A0A-39B6-4BEF-AE9A-96AC3011F8AC}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: dns
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{C9B1AD3A-3104-4B5D-AA25-4A2569F0CD78}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: SRVBLB
				: srv_test_BES_EX
				: srv_exchange_test_bes
				: Srv_PreProd_BES_EX
			)
		)
		: (rule-63
			:AdminInfo (
				:chkpf_uid ("{C96CBF93-4EEC-430B-BB6D-118E62A9DA32}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{9936CDD5-2722-4B2C-A9A9-F9BB30F1C3C2}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{58849361-A3D2-4A29-8C85-11B0B63805E3}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{FFF4CF75-6F66-47A2-8CC2-D0C26E7326D9}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{F99DB68A-6FD0-473B-99AC-34CD5788472A}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http
				: https
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{CFB98835-EFFC-4C45-803E-1E69753E5BD6}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: srv_test_BES_EX
				: srv_exchange_test_bes
				: Srv_PreProd_BES_EX
			)
		)
		: (rule-64
			:AdminInfo (
				:chkpf_uid ("{8E4C346F-6048-426F-8C23-D6E00F95985A}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{266CC742-C947-4B19-B18D-AB131A20CE13}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{85C98A8B-0AEE-459C-B124-FDE562D5587F}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Adresses_Publiques
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{1650F94C-5139-4AA8-9131-7865DB4E1DA1}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{635194B9-4ED4-404E-AED9-C30BEAF5ECD8}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{F412AEFD-1E10-4321-AB11-33F21469CC79}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: SRVBLB
				: srv_test_BES_EX
				: Srv_PreProd_BES_EX
			)
		)
		: (rule-65
			:AdminInfo (
				:chkpf_uid ("{B7C4B8FC-A4F2-4D93-909D-1AA8FCEE0147}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{5ABD6D85-DD2C-4EE5-8E26-103157042E08}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (VPN_aes_sha)
					:Table (communities)
					:Uid ("{D4275208-E350-4878-9894-76DF32FC7F44}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{F4593791-49FB-40FC-B1F7-5BA8E97DE95C}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: PeerNet_Ferma
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{6A4D4C1F-0784-4921-8DA4-F5E255279E89}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{899061A1-1FBD-4A3D-8931-E4DB65C2C2B2}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{05F7ECED-9448-4933-8D21-B1219CB4E6DB}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Ferma_PSI12
				: Ferma_AOMC1
				: Ferma_PSI11
			)
		)
		: (rule-66
			:AdminInfo (
				:chkpf_uid ("{B0F22644-2DE6-4AC8-88CA-05109EE9AAD0}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{AAA58D14-00E9-4093-8F11-5A294084A696}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (VPN_aes_sha)
					:Table (communities)
					:Uid ("{D4275208-E350-4878-9894-76DF32FC7F44}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{C4988876-244B-4E91-B7E9-5D6B01019ECF}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Ferma_PSI12_NAT
				: Ferma_Web_MSD_NAT
				: Ferma_PSI11_NAT
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{A0C1874B-885D-40AB-9450-FE460F335128}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{75C91D87-EA27-4962-964F-D6534D4F9CE6}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: telnet
				: FermaT1
				: FermaT2
				: FermaT3
				: FermaT4
				: ftp
				: ftp-bidir
				: icmp-proto
				: ssh
				: http_proxy
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{20EC824D-13EF-4737-ACB7-F14255EBFC57}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: PeerNet_Ferma
			)
		)
		: (rule-67
			:AdminInfo (
				:chkpf_uid ("{DD394089-DA0B-4272-90C4-C7C2740599A3}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{3F11596A-F150-489C-ACB6-850D9716B8FD}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (New_VPN_Invigo_Roscom)
					:Table (communities)
					:Uid ("{8FA519CE-2889-425C-9071-499E93FD522E}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{A1B5DF15-7D25-4462-88D5-3312D6105194}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Gr_Srv_Invigo
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{445EDF58-D611-458C-A53E-78D49686EF07}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{DEAE39C7-7EE7-4482-9F40-638D52686A50}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: ssh
				: icmp-proto
				: TCP_1158
				: http
				: sqlnet1
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{375AC3BA-653D-4698-9132-50AAC66003F7}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Gr_Remote_Invigo
			)
		)
		: (rule-68
			:AdminInfo (
				:chkpf_uid ("{24D5CD56-F54E-4241-A670-396DAECC2665}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{2BF4C5F6-A8A2-4969-BF8D-F765AEBE4DC7}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{919C13DF-B8C3-4121-8E7F-1E23098D63B5}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: IN_NS5GT_priv
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{D164EB1B-A466-4B35-BB62-9C2C45FD4A22}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{42009048-B6F2-4068-B53E-2994823F8114}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: ssh
				: ssh_version_2
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{F93AFADC-167C-40A8-8D8C-08E72D60469F}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Fw_Alcatel_RAMSES_Flows
			)
		)
		: (rule-69
			:AdminInfo (
				:chkpf_uid ("{D54526F1-005F-4122-91A9-7C166AD3DEA6}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{9D205888-8DB3-4D96-B562-85D483493DEB}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{B205786B-4158-495A-955D-68EC15DEC185}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: IN_NS5GT_priv
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{8EC02467-AC08-483A-923A-0CBD65CF906D}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{DC23F5E6-74B3-490A-BAEC-426C503BCD6E}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{69176691-DB80-4A45-B6A2-2AF048764025}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Peer_RAMSES_Gateway
				: Peer_RAMSES_Gateway_SingaPour
				: Peer_RAMSES_Gateway_US
			)
		)
		: (rule-70
			:AdminInfo (
				:chkpf_uid ("{F7CD06A7-46E5-471B-80B4-9B32FA2992AD}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{E5B2684F-E5B2-41AE-A2DA-2B564DDD487C}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{47FFE15C-F005-40B1-A021-07BB890FC139}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Peer_RAMSES_Gateway
				: Peer_RAMSES_Gateway_US
				: Peer_RAMSES_Gateway_SingaPour
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{4FEEC3BA-1476-45AF-9EB3-F0071C3FE7BE}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{3219177C-642A-4EC7-B06B-E881D5ECC9E6}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{F0660C51-063F-47DF-9B11-5873642104ED}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: IN_NS5GT_priv
			)
		)
		: (rule-71
			:AdminInfo (
				:chkpf_uid ("{E5F41383-04AD-4664-8C8C-E8C2D1632A85}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{DB092BE4-1107-4E3B-99D8-00A162888768}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{3FF4BABF-EA7E-4593-A594-81B4D6FDFCD1}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: IN_NS5GT_priv
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{15146CFE-C296-4A5F-9712-84AEA83CD7DA}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{C73B586B-D770-411D-9ED5-4D2C11058229}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{70892D46-79ED-4B72-ACDD-63CB17A47335}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Fw_Alcatel_RAMSES_Flows
			)
		)
		: (rule-72
			:AdminInfo (
				:chkpf_uid ("{BC241AB1-2467-4912-8D51-22B36E9B86D2}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{1B53FC2B-F54A-4236-838D-DC13C43614B5}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{D9519DA9-2801-4F74-9868-6302231C6620}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Fwent
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{746FF2B3-D1C8-4240-BBCB-3DF3472F02CE}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{15CE6271-7C93-4A5B-98C7-B78CBD5493AF}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{5E657B75-34AA-4637-84FC-4F79ABCABDBF}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: IN_NS5GT_priv
			)
		)
		: (rule-73
			:AdminInfo (
				:chkpf_uid ("{8E50B103-595A-4733-BC4B-51B72518CFE7}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{BB50CCC3-CCC8-453F-A885-DFE6C4175459}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{CF635C0C-3090-4A1A-B047-A99E8ACE8CF6}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Peer_RAMSES_Gateway
				: Peer_RAMSES_Gateway_SingaPour
				: Peer_RAMSES_Gateway_US
				: IN_NS5GT_priv
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{C5F8C523-9122-4A72-A23D-D45367FDF388}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{AA4F30DC-D81C-416A-9BA1-470C29A965B0}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{0799130E-F617-4B79-81C1-32E477C27E78}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Fwent
			)
		)
		: (rule-74
			:AdminInfo (
				:chkpf_uid ("{3D572B8A-3BB0-4D71-B9D3-82E5E4652152}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{A2FA05C2-1F56-45F3-89E3-7DF4A46FB7B3}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{F97799A5-379A-45B5-A6FA-5FD7A7A6D6AE}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Fwent
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{41F41653-8FC8-4440-9F39-D8392A672A7B}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{63D2AB81-B6E9-458E-9B0A-43B2CFF26FDC}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{5D671537-123D-4112-BE24-6F4F5F965C18}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: IN2_ns5gt_pub
			)
		)
		: (rule-75
			:AdminInfo (
				:chkpf_uid ("{A4C7FD10-98DF-45B5-A1B1-562D1243DD05}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{DEF8F415-1ACA-4DDA-AF7D-D1F45215DD86}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{55EF594C-85E2-4104-9604-E804D8F8B37A}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: IN2_ns5gt_pub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{B22A53C5-3649-40D6-8B4F-149975D6E194}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{7C4B8572-CD68-4785-8B5B-71B50E335810}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{5F0D123E-CD41-4D4E-BB21-8764F01CCDC2}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Fwent
				: proxent1
			)
		)
		: (rule-76
			:AdminInfo (
				:chkpf_uid ("{66265673-463C-4B7D-9AD0-FCFFF6BB65A9}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{2E9FB840-69DC-40BB-8DDE-7EC98828F9F8}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{6525D1AE-EB27-40D9-A395-536C7F15F349}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Net_PASES
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{41884BE6-4C4C-464C-B0FD-2DFD16165595}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{38DAAD34-9A17-4B11-8421-7978037BAF59}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: snmp-read
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{76A8A633-7B1F-4838-B2FD-C8598537ABC1}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: SI_SAdmin
			)
		)
		: (rule-77
			:AdminInfo (
				:chkpf_uid ("{5E6CB0D2-184A-4B3C-ACEE-AB55420CA80E}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{5D09AAAD-306A-41F3-B1A3-16DEC60C2EF3}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{7A29B1A0-2769-4207-AB22-BE820610324F}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Net_PASES
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{58DE7181-1632-4EED-9A18-B65E8046DC33}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{877659F0-3A7D-4BCC-9CA8-F3DE0056C72D}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: X11
				: X11-verify
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{49765A3D-8167-473E-9388-31572CF7FD92}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: SI_SAdmin
			)
		)
		: (rule-78
			:AdminInfo (
				:chkpf_uid ("{E82F0470-DFF5-4C53-B77C-54A8DFB86C70}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{C23B975C-0DDA-44EB-92BF-AF24684C78ED}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{83796F1C-C6E1-4C6A-BF63-B7D8D5068EEC}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Net_PASES
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{96472B30-9859-4FBB-ADE9-AA42D6397F42}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{8741BB7E-A6F0-49D3-A1DF-87EAD2E1DFF4}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{F794A0A8-3A98-4228-AA47-A3C49DEBB84F}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: DSI_DIO
				: SI_SAdmin
			)
		)
		: (rule-79
			:AdminInfo (
				:chkpf_uid ("{1604C63E-CA79-4984-9477-B4237A39267C}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{59079B07-9129-491D-ACD5-6D88C5BCC6A7}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{D2E25A04-31BD-4E90-BECB-96E3EC71D7A2}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: DSI_DIO
				: SI_SAdmin
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{F4E566EE-3272-41D7-A87D-672C10405B7B}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{ADE2C213-538B-40A2-887F-7B236D34CE77}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: echo-request
				: tftp
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{06A57971-274F-4C2A-8814-BF4B3B53A8D1}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: swserv1
			)
		)
		: (rule-80
			:AdminInfo (
				:chkpf_uid ("{60F4C75D-2440-4894-A6A6-69BC2CEE44BE}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{D38BFDA2-6242-4D7B-8B7A-308C7E8F4E90}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{A4FF0095-7EB6-4D1B-ACF4-CDEAD59432C3}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: DSI_sadm_BZR
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{C878FA06-750F-441E-A2E2-DD766BDA1872}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{C4B1DB94-3F5B-4209-9755-F169A091C1CF}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: ftp
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{55E6A670-D874-4452-94C0-CBB920CDC63B}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
			)
		)
		: (rule-81
			:AdminInfo (
				:chkpf_uid ("{08E334EA-8A22-419F-8C8E-4EBBFEC06642}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{82781A21-0C9B-494B-9BD5-3F9F5D4AA6C9}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{382DAAE3-CD04-48D1-BA21-515605989DCE}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: DNS1_OMA
				: DNS2_OMA
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{7E871A7C-7439-43FD-975B-D1103FB044E0}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{09DDBBD8-D87E-4997-812D-6579948D1FF3}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: dns
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{44EB2688-7080-4051-A39F-E93E9643D731}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: G_srv_prTech
			)
		)
		: (rule-82
			:AdminInfo (
				:chkpf_uid ("{502DE994-87C4-420F-921E-A24E9F146F7C}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{28B4BD39-FEA7-4377-BE09-2C4AFBCA6745}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{EAD3FC34-9BAD-4CE4-9F9C-3EE14713B16D}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Site_RUN_SMS_FR
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{C17D0905-329D-471B-AC57-C31B46FD900B}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{6D9CE22C-D6A6-4F58-8305-C3589C1DD73D}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{11FE1DA4-B5EB-4CE8-A2D9-CD8100F6CD3F}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: G_srv_prTech
			)
		)
		: (rule-83
			:AdminInfo (
				:chkpf_uid ("{29FF1909-CD29-4340-89EA-A51D9A374BB3}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{EF795DA7-D280-4CCC-BB92-1476AFBCC5A1}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{4D013D92-1808-45C5-B083-8FB8C9A05BEE}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Site_ftp_clients_afp_com
				: Site_ftp_cpth_ie
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{8E23FBD3-B5A1-4011-B708-E52BCC36CF12}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{96B8D153-4DEF-4E68-BEA0-F63F519F4FC8}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: ftp
				: ftp-data
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{4222A43D-449A-42E9-B9E8-8B5876E546F6}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: G_srv_prTech
			)
		)
		: (rule-84
			:AdminInfo (
				:chkpf_uid ("{795E040E-1C04-4745-8316-E70733A4C018}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{B614AC29-5461-4179-A117-28A9F34C3539}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{6869137C-04A3-4D2D-899E-BA20D3FBD214}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: PushMail-provisionning
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{F4766BF9-AC48-4F0F-A54A-87F6C74316CD}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{0E061DAA-68FD-4CB7-8A72-61C1147224E2}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: tcp4226
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{BCB6C798-29D7-4360-82A2-8455AE9E1D63}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: G_srv_prTech
			)
		)
		: (rule-86
			:AdminInfo (
				:chkpf_uid ("{99835D72-8B0D-40F6-A190-7C758551B40D}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{492E4981-AA17-4583-A455-3544CBAA1639}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{575AF17B-1D03-4350-8C51-5DEEC5C1AB43}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Srv_prtech_pub_SmsPlus
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{E392257B-15EF-4803-B5A7-A5C91F984F60}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{7448C892-E193-449B-B7EE-1C1426D9CEF4}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http_9080
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{DD4122C2-6270-418C-ABBA-A8401E45BDA7}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Srv_test_Coralys
			)
		)
		: (rule-87
			:AdminInfo (
				:chkpf_uid ("{9D235950-8087-48E0-BAFC-2BEA14C8F7D0}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{83AE4FD3-002D-4192-8679-4FD9817EBF14}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{CA8EBB43-0A04-423E-A757-49CE77EABD0F}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: srv_Netbackup
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{AB495AC7-B707-46B3-87CC-7A7BEEF634EC}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{DE373156-4B98-4C10-9FD2-1DF2056325E8}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: bpcd
				: ssh
				: ssh_version_2
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{2EB792B2-7021-468B-A21B-096E1A0604F9}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
			)
		)
		: (rule-88
			:AdminInfo (
				:chkpf_uid ("{02BEADB4-4239-4234-A8D5-72BC0E9BFB35}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{F4B1C1B9-95EC-41EA-B5C5-2DF83828E4C9}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{4E54398C-D4F2-4BCB-B00E-353448D1976D}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: ProxyReverse
				: proxyreverse2_priv
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{8736D07F-4CE1-492B-95BB-CD03E510CCE4}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{8F1773DB-F2CB-47C8-B327-093323606EB4}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: bpcd
				: ssh
				: ssh_version_2
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{039BD48E-D06C-40B3-8862-D69B684E4A14}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: srv_Netbackup
				: srv_netbackup2
			)
		)
		: (rule-89
			:AdminInfo (
				:chkpf_uid ("{B80A74D1-FC37-410B-9EAA-B0C75062D5A3}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{0237FDF8-7C5B-4CEF-876B-1613F8E1BE14}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{6FEFCF21-1FCD-43FF-AF0D-DE45B977CAF4}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: srvj001
				: srvB007
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{317F008E-BE0B-401E-B7AC-FB0BC8599131}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{218E2324-C203-44C6-A781-FE06E1C08C84}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: NBT
				: microsoft-ds
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{B7AA20A4-E55A-47ED-B583-E0D124A5CCD3}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: srv_sva_dartagnan
			)
		)
		: (rule-90
			:AdminInfo (
				:chkpf_uid ("{F49F1318-24D2-4E4F-9DC6-ED8B97CAF40C}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{FE2FE477-8C0B-41E8-ADCE-60979E93CEF8}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{AF97FCA1-C561-4425-9468-99702FD5EE53}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: srv_E-vidy_orange
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{A9E593B0-4B85-4933-BEFF-3C5FB0DDBCC1}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{6F2B744C-2AE7-4ECD-AD00-86684538EAB5}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http
				: https
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{DF1F2642-599C-4194-A7CE-E698834B91AE}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
				: Net_Orange_Money
			)
		)
		: (rule-91
			:AdminInfo (
				:chkpf_uid ("{11860782-2BAC-45A0-BAEF-DE6710351294}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{DA67CBF3-3E39-4C13-929A-019AA5855473}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{B6EE6E84-8A06-42CD-B866-DD62E7908080}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Srv_httpent
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{21D08456-3A18-4AEE-85CF-EB6803C09AFD}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{84D93A96-F681-4668-A80C-39D45098B5AC}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http_proxy
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{5B0129FB-3493-4DA8-9187-284122CDDA69}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: srv_sva_dartagnan
			)
		)
		: (rule-92
			:AdminInfo (
				:chkpf_uid ("{0E30AD82-DEDA-4C9D-AAE4-4B501AEBFD65}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{FCD94BA6-2108-4259-B3CC-218681141D3F}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{B5069DF7-9779-4587-9BB7-4873EE955083}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebRadioPub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{7A96C059-6247-4AFA-8A70-6AD688F1E58A}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{D9BEC7B9-E4B2-4940-AFDB-BCE7CF849346}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: RAdmin
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{FC9DE21B-B07C-4A42-B67A-285307A761D0}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Adresses_Publiques
			)
		)
		: (rule-93
			:AdminInfo (
				:chkpf_uid ("{7E0464D8-1D2E-4DFF-92EA-D43AF2C4F1C1}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{2D87194F-B31F-439D-B6BF-16CA4AF42D0A}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{150EB1E6-5431-41E1-A230-4E37F83CCB5F}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: srv_sva_dartagnan
				: WebRadio_admin
				: WebRadio-Test-MSC2
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{BBE72D28-1B41-4F48-A458-EB5617502E8E}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{0EED6B70-D285-46BC-B67B-D535CCDF1798}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: NBT
				: icmp-proto
				: RAdmin
				: MS-SQL
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{1A4494B6-6483-422F-893F-62BDB0044E05}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: WebRadio_admin
				: srv_sva_dartagnan
				: DSI_SVA_RKP
			)
		)
		: (rule-94
			:AdminInfo (
				:chkpf_uid ("{FF5299AC-599F-4E91-B068-2B73A21E497B}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{BFE185E7-FB80-40CE-A2F0-FF1D27F96FB1}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{3E56EA50-1135-469A-8B62-5D029A157C26}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebRadio_streamer
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{695BA9C0-6766-48F6-B2EA-233ED06172C5}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{E814036E-B92E-420E-B1F4-2FB2C6135301}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: tcp601x_webradio
				: udp601x_WebRadio
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{7D163505-5946-4786-BC00-BE212CCB02DB}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: srv_sva_dartagnan
			)
		)
		: (rule-95
			:AdminInfo (
				:chkpf_uid ("{2DDB5E9F-8030-44CC-9E80-61B5269A19A2}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{C8F84B65-FF43-4AFD-BFE1-74E07AB4A919}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{BCABF289-9586-422B-B41B-D0A9A1B48468}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: srv_sva_dartagnan
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{B9FD3D45-CB76-40E1-A70C-353D889DBE1D}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{691718C1-35EB-4226-8817-1A1877AE188B}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: tcp601x_webradio
				: udp601x_WebRadio
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{9ED371BE-0544-4A92-B50D-AFF8CC66BF3A}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: WebRadio_streamer
			)
		)
		: (rule-96
			:AdminInfo (
				:chkpf_uid ("{B8E0D062-304D-4E3B-9EB8-BE515B799A43}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{B34D59EC-8471-4472-8F2D-534AA67577CE}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{AB7D6C8C-AD8E-44DA-B08A-6BDCDF80DAD3}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebRadio_Admin2
				: WebRadio_mp3_multicast
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{81F6B770-BDBD-4FA8-8E66-266EFF2736A2}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{FC531A30-37DB-49B2-B88D-34F96E8E281F}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: tcp8001
				: http_8000
				: icmp-requests
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{A855BC8E-615D-4F6C-854D-5BC2DCEAF71D}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: srv_sva_dartagnan
			)
		)
		: (rule-97
			:AdminInfo (
				:chkpf_uid ("{4B0C2A37-6132-4253-8352-3799BA652909}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{49E25577-4F54-4252-AC53-7C0E1B483DB2}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{24790A9D-0166-4BB6-BF61-69F68AEB400A}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: G_srv_DNS
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{FC0B473D-C17F-4906-B789-20451B9064F0}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{E848F862-A614-48DC-BBC2-B02F6B05E9A2}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: dns
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{C68DDFF2-8839-4504-A1B1-DB5D944C3050}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: srv_sva_dartagnan
			)
		)
		: (rule-98
			:AdminInfo (
				:chkpf_uid ("{4E974B55-586A-445B-8759-373B0D89ABB1}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{0B042CC0-DB48-4BB8-A208-94C71F15E248}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{3B0C99AC-BFCD-40B4-B40F-C1DD3A421789}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{28F43477-6172-4133-ACF5-191A4E744147}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{3E448A49-1E72-4428-9E1E-0B3A692A4421}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: ntp
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{024B0FD4-9C91-4C5A-8EB2-F88CB84D84AC}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: srv_sva_dartagnan
			)
		)
		: (rule-99
			:AdminInfo (
				:chkpf_uid ("{B8DE8B20-2ADF-4530-A477-E98A96F594B0}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{0FEF50F9-EE52-4848-9110-78E71970E576}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{133F555D-C9F7-4584-89B0-C3A07DA1F6D7}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: HttpPortal_pub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{ED63C94E-2F53-4A8C-9B9B-46EDD85B369F}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{F366A97A-B076-4EB2-86EF-EA27DE499296}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: ssh_version_2
				: ssh
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{C7B67D6F-45E1-494D-BE7A-81A6549B7D04}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: WebRadio_webportalContentUploader
			)
		)
		: (rule-100
			:AdminInfo (
				:chkpf_uid ("{BFEC863D-4AA1-486F-8F39-F8F4A7FE444C}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{9CF9B585-04C4-4771-9326-1A0A1BFEE643}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{54A738CC-979F-4458-9B1E-5F71BC4702CF}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebRadioPub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{C0481550-0174-4C0E-9E21-59774E6C709E}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{66394290-1DAD-4C49-8DF4-DE95F8A90C3A}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{AF8C1BAE-5814-40D8-8FB4-D95FBB3D74F3}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: orapub-int01
			)
		)
		: (rule-101
			:AdminInfo (
				:chkpf_uid ("{C5DF8F0F-D4DC-452C-B6A5-157FEE711ED6}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{54CD5A6C-94CA-42B6-86C2-9927C1858881}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{5B5C3BE7-B598-4F78-8877-6331A1865F07}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebRadioPub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{0138B922-2E47-4EE8-B138-7F75D5B78361}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{7BC2D866-2EB7-40D1-B78C-9A8BE07C3DE5}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: tcp601x_webradio
				: udp601x_WebRadio
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{5DD6F0BB-2691-46FB-96DC-4BECB54495CA}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Adresses_Publiques
			)
		)
		: (rule-102
			:AdminInfo (
				:chkpf_uid ("{2F01A36B-8017-4825-8385-E1F04BE324CA}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{64592F44-7B4F-4233-AA23-7596BC68A51E}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{570E4FBA-F5FD-493A-B0AD-5AFA5A86A6FE}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{BF3712DC-AFB4-4689-96B2-2D4EF1E7F671}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{02E208A2-F324-4DC3-A782-D22AAE183AFF}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: tcp6020_webradio
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{920CA15A-44D6-48F1-BA4B-58C64F4594E5}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Adresses_Publiques
			)
		)
		: (rule-103
			:AdminInfo (
				:chkpf_uid ("{2C54434F-B0E0-46DA-9759-2C7A7DC01B66}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{EA234FBD-2F7A-4751-BBC8-85D5C0121C6E}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{5170A0DD-3B4B-4828-8732-A5E7F743AE73}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebRadio_mp3_multicast
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{729F38C0-A88A-44CC-BFA7-7335C54ECAF5}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{14379989-D423-4C77-B490-6C13B239E8BB}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: TCP_8010
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{EEF84DB8-0B19-4BE3-B656-FF961AB4D23E}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-104
			:AdminInfo (
				:chkpf_uid ("{87D414EE-356D-4E89-94F0-375CB784DF0E}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{17560769-F884-40A5-A7EB-80A70B1FD6A6}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{A57459F2-C32F-46D0-B17C-A8BF3F54B061}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebRadioPub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{463F52D5-8660-42FD-9350-AC2E2B4F3DAB}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{A009DD61-B525-4CD1-8735-CFBFE504C5B7}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: tcp6020_webradio
				: udp601x_WebRadio
				: tcp601x_webradio
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{5B3199A8-7909-4BAB-BAB6-35E18D6A916F}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Srv_Proxy_TMM_Priv
				: Net_SI_OMG
			)
		)
		: (rule-105
			:AdminInfo (
				:chkpf_uid ("{D4503D10-FC48-464C-9C3D-0A163B9FAA3C}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{A524D77C-6DAF-413E-B346-BA5C3DAC0D51}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{8412F69E-E456-4905-AE8C-E98BD7AE275C}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebRadio-Test-MSC2
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{29993A62-6C36-45B6-8241-AC2A24CB8AB7}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{A2A0F05E-19F5-4667-B2DB-C51749F52C18}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{BFDA17E4-BCE1-4A72-9479-DF69B44552CE}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Net_SI_OMG
			)
		)
		: (rule-106
			:AdminInfo (
				:chkpf_uid ("{684D7AE4-4626-46A8-8369-4F2383608E9E}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{607B236D-65A9-44CA-8685-53A2AC817ACF}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{2A8787B1-9975-4E36-8E66-B7FF26FA28AC}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: ntpi1interne
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{3A2CF788-8AA6-4104-ACC8-C40E5E8FE423}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{B2D87BAB-F0AA-4169-A12D-949974D91843}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: ntp
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{DF1E33E9-D7DB-4232-BCA4-F3B274881636}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
			)
		)
		: (rule-107
			:AdminInfo (
				:chkpf_uid ("{CCD9A88F-301A-448E-B8BC-A0EE2625FCAA}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{A69BDB19-6F6E-4149-9675-A65128ED28C8}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{C521A076-B12D-4076-9B65-9F2AB8EC2868}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebMail
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{30ED96B3-1B0E-43D2-B412-0D3EBB9C5337}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{75E81EA8-7BD7-4FC9-BD8C-56B5C428724B}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{BCA0CCEE-9991-4A09-9D54-55ACD31ADF04}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
				: srv_ip_OrangeView
			)
		)
		: (rule-108
			:AdminInfo (
				:chkpf_uid ("{0F9F0D3D-B559-4607-919F-E400B2CF641F}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{8764F096-9F91-4B5A-9D10-E0B9DCD5C15E}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{1BF6C98A-7450-4ACA-BEE6-A560496DF748}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Zebra_webserver_cluster
				: Zebra_webserver_mb1
				: Zebra_webserver_mb2
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{50CA1B7D-4B61-4B5C-B94A-15B9B0B89EB6}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{F146CB42-0C8E-453D-98D8-E7CB8C05105E}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: TCP8093Zebra
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{8B73F6A8-2986-437A-BB27-B01C3B6930B2}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
			)
		)
		: (rule-109
			:AdminInfo (
				:chkpf_uid ("{26B21207-820D-4145-AB6E-365B5883E530}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{B9C3D4C3-1ED2-4106-BAE3-4A8B5CAEC3CD}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{F821C618-BD2F-4B19-A191-B774BB350244}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: TestZebra2
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{00E185D7-6841-4CFD-99F8-C14D8DF930DF}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{F3FDF1B7-8627-4F27-A23F-246BC188F491}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: Napster_directory_5555
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{8EDE54CF-7333-40D5-B6CA-204657ADBB66}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
			)
		)
		: (rule-110
			:AdminInfo (
				:chkpf_uid ("{0099414A-BADE-4B16-8417-E22146CA6DE1}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{8ED8BAE8-EA5A-4A8A-A59B-31488959C2AE}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{79E45E60-70D3-4D59-BA36-AF634A1CE39D}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: DMCvirt_DMC
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{A9E7D32B-220C-4408-83F9-B2C06E4C2CEF}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{8F7A418A-276E-4C29-8918-2E4A40A880A6}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: TCP5040x_DMC
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{CC508A46-72C2-4017-AAE5-D8A4F2BDD9A0}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
			)
		)
		: (rule-111
			:AdminInfo (
				:chkpf_uid ("{1D41B014-1959-4DAB-A1CB-131F4F78C33D}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{39503B33-AB98-4875-A72A-15F36706BC71}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{6B2EA769-6B33-42FF-BA84-803DCD0F387E}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: MMS_mmbox
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{204C152C-AC48-4451-B2D8-CC55210C3E87}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{35AB5703-13E0-4692-9BC9-39D073035E3B}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: TCP2020
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{E107AAFC-2E60-4CCF-B4C3-F3107B5EE7A7}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
			)
		)
		: (rule-112
			:AdminInfo (
				:chkpf_uid ("{D2C5DF70-4B4C-4D0A-9860-D5C756F489F5}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{58098EC5-A8DA-4772-8CFA-9F031BD305CB}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{23DAECB8-A961-4739-B31C-9A41655B6624}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: G_srv_prTech
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{BA6DB4FE-7083-4991-8D41-9FFCC8DD153A}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{A0E5E4E1-7A1B-4EBB-B646-4062978444BC}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http_9080
				: http_proxy
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{9293D34F-F43F-4461-A4C3-3A750FEF605D}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
			)
		)
		: (rule-113
			:AdminInfo (
				:chkpf_uid ("{E3575A10-9EF6-41DD-8301-B16012855F72}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{228F753D-164A-4A34-9802-A1F58AFF3410}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{90C7513D-257D-4218-9451-0AE7D9304FAB}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: srv_sva_crbtPortal
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{F39436F0-2FEE-48A9-AD39-FABB8869086E}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{B2EC80C8-75CF-4427-A42D-42FAAA0AF091}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
				: http
				: icmp-proto
				: traceroute
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{ECAD58BF-0170-490D-B4B6-C1597824F405}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
			)
		)
		: (rule-114
			:AdminInfo (
				:chkpf_uid ("{37339F28-59B8-4FFA-9039-3DBC34302C18}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{CBDEF015-279F-44A4-B46E-AB1AB55408E1}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{8121965E-2980-4888-830A-3B546E8E26FE}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Zebra_TS2
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{118E0486-4C8E-4202-B5D0-785FDC99D11C}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{9411C3AA-1796-4EFF-8E88-5815D856DECD}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: traceroute
				: Napster_directory_5555
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{3E588073-6697-4014-981D-B05443F967C2}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
			)
		)
		: (rule-115
			:AdminInfo (
				:chkpf_uid ("{9BB52816-61F2-443C-BDDC-D5FCDD780BCE}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{7140B6C2-22B1-4919-93A5-E0940995DBFA}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{596AD142-84F8-4A00-A0FB-AB9CE2A979A5}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: srv_ftp-broadcastonair._fr
				: srv_s155945973_onlinehome_fr
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{E6F421DA-A20D-4D29-8E93-3620D69E4437}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{BBB7BFF0-9FF9-4130-B21E-840A60287FAC}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: ftp
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{269CC4CB-7E71-40C4-9DB9-27A1B04321D2}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: DCCS_DVR
				: Borne_Internet_DMCC
			)
		)
		: (rule-116
			:AdminInfo (
				:chkpf_uid ("{99106BFF-5C24-44E9-8F79-16473BD44162}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{CFB0A772-ABD8-4538-B26F-9221CC7430F7}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{9D8CA59E-4396-4A08-9088-C069D1564AAB}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: srv_ftp-broadcastonair._fr
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{87FB94B5-927F-4EFE-862F-12787C33E271}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{ED9962FF-36B4-4F17-8E92-4F69BB555DA3}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: ftp
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{D180CA9B-5132-4E52-A8B9-D15587E6467A}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: DCM_RHM
			)
		)
		: (rule-117
			:AdminInfo (
				:chkpf_uid ("{B1730948-1342-4FF9-8911-942BAC451D3B}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{86CE6C39-89B7-4D3A-802F-5E7B8E7A288C}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{767B38EF-1D7C-4583-98CE-4E70009EB511}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: srv_prTech02
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{4520C178-36E0-4492-AFF0-00D75A245896}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{03417DDF-B24E-4463-BFB4-6F15834841B1}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http_proxy
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{4AD006CB-3572-4AE3-B4F9-586AF727A534}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: proxyreverse2_priv
			)
		)
		: (rule-118
			:AdminInfo (
				:chkpf_uid ("{C9AB35F3-B329-4201-BB0E-3ED09F3687B6}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{251CB204-19BD-40B7-8DC4-50C387C5C398}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{6DDA90B4-FDBE-4C54-8950-1BCE5A8FD22C}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: srv_prTech01
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{46B9AE4A-503D-4A9A-8314-D22B16BE03CB}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{9437D9CA-4497-4146-A893-030809ED45D9}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{67E8BE34-E6E8-4D52-A6EC-12AD2B65BCC3}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: proxyreverse2_priv
			)
		)
		: (rule-119
			:AdminInfo (
				:chkpf_uid ("{3360AAF4-66D1-4F33-8F12-7A4E1367092E}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{FC763CF0-AABD-4BC7-B9D1-C13D49BC8EA2}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{3E1AC31E-F564-495D-BE7E-EFBA3A327B69}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: proxyreverse2_priv
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{CF1741D1-7BB1-47E0-A754-6A6FEB3C3FCB}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{B88C8621-0ECF-4172-998B-761B3177D495}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http
				: icmp-proto
				: traceroute
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{227348C5-0AD1-4378-8479-AFA85D1D08A5}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: srv_portail_bacc_privee
			)
		)
		: (rule-120
			:AdminInfo (
				:chkpf_uid ("{172E17BB-3D18-4D23-8E92-E2AA451B32EC}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{051B3EEE-5369-4217-B44C-1FA6D410F396}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{43785506-455D-4624-A56E-013ADCC24994}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Srv_Prtg_ISP
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{E450882B-F7B1-48BB-A6D2-4A4A5BFF44E2}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{483D11AE-0C2B-40B6-9B9E-5C9D99A41A58}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http
				: icmp-proto
				: traceroute
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{DD272B17-2F78-487D-A1C2-AD3D119540A3}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
			)
		)
		: (rule-121
			:AdminInfo (
				:chkpf_uid ("{3A74780E-03B0-4FC5-96E8-E4903C165267}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{4DF79BAB-14C3-4126-865E-0DAEFF99B30B}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{9EDDC559-785A-407C-841D-5B8BB046D442}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Web_Online
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{813FF855-3A46-4F03-853D-35B76A7D93DC}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{6E0A6D2A-A81D-483D-B92E-ECD7F03AD4B0}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{3E69AF31-0D87-466D-B087-485B29CFA40A}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
			)
		)
		: (rule-122
			:AdminInfo (
				:chkpf_uid ("{5E26D9C0-E9E5-4D57-A9D9-C460F40C03E4}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{5315DA0C-7A30-4C11-BB74-C13787172CEB}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{7D64E685-FE74-4867-8F6E-052B7FF103C2}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebMailServerPub
				: orapub-ext01
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{B5D92EF9-ECB9-422D-95C2-7C74976EF22B}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{07ABAEAA-BB3C-4A05-9D43-46FC6524F627}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http_446
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{2BA84D89-3AAD-4888-8057-E852F4115B55}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-123
			:AdminInfo (
				:chkpf_uid ("{57AA1658-5F21-4C88-A098-3F0111C1A4CA}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{45E0327F-239C-4E9C-87CC-A02D6D4235AD}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{065C95B1-DFD0-4681-B622-94D82D29FFD2}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebWzwOnlinePub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{6CBF054E-984A-4E8F-A872-75D4C371DD66}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{7D934DC0-7755-418A-B26B-F07D3BDADC8C}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{BD533920-0EE7-4DD8-BA62-6FD04FB8951A}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-124
			:AdminInfo (
				:chkpf_uid ("{9D3BC48D-C214-4F26-A2AE-988AAFB02B87}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{AB049783-2F53-4165-98B0-D585ED439390}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{79844378-EDAA-401C-8C5D-49F0ED3D68C2}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebNewMMBOX
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{BDB1AB53-37B8-4779-8E12-1C735995E7EA}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{8C001164-00E6-4326-8670-70C0D7E7D8D7}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{AE583E23-256E-49E4-B771-D62854A92D81}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-125
			:AdminInfo (
				:chkpf_uid ("{F180C1D6-D4F3-45A3-95CD-82F9EC34E7DF}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{A5DDBBDD-B95A-446F-851D-BAFD87D312C3}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{A905A263-FA21-4103-9384-BCCA60E61B39}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: MMS_mmbox
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{16DEE126-5C21-4A20-ABF5-42A78638AE11}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{CC13CDCF-17D1-47F0-8BB4-7BCD74F771EB}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: icmp-proto
				: tcp8001
				: traceroute
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{4515B6F5-3CBE-420A-ADD7-39D57EDDB394}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
			)
		)
		: (rule-126
			:AdminInfo (
				:chkpf_uid ("{43BFFB82-4840-442C-A811-70FB5B965F00}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{3334CCDA-ED9B-4A30-8D65-871C6A7D8CC3}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{16C8E261-F6E2-4E87-B827-8E5672E11FDD}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebRadioPub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{FAB9BB6D-463E-4EB9-B9F3-C4C2AFA32093}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{F6D82303-23F0-4482-B8C2-BEBCFF341E64}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{C2BE3032-22F5-4B4C-80E8-F57E5E45BCD5}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-127
			:AdminInfo (
				:chkpf_uid ("{E7700E10-A98C-48F7-BFC3-A17D5273A0FD}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{F0020661-A9C6-470F-B74D-82D41627EFCC}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{37F9D639-6560-4CC9-802E-AF91BCE67891}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebMailServerPub
				: orapub-ext01
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{5B173E67-C5B8-495F-B4BA-890BF18516E5}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{CD9A6FE0-BBA3-422C-8AB7-E246DC16133C}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
				: http
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{C4F55CEC-7146-451E-A7C3-913C71B98AAD}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-128
			:AdminInfo (
				:chkpf_uid ("{30118A7E-1344-49C3-9627-4630BE3DA2F8}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{B3C967AF-FEED-4132-A0C3-C021A2D8C20F}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{866241D7-2A38-4F54-A0A5-17B9C1D65797}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebMailServerPub_fun-tones
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{8FA6583C-43D6-4849-91B6-05539295E9CE}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{BD38BDDD-E380-4D21-BECE-5437D16B0721}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
				: http
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{A4C4EE64-9CDD-4C71-BB17-2D1D3506F150}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-129
			:AdminInfo (
				:chkpf_uid ("{64E15AB9-03A2-4744-A110-4A8358A7FF2B}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{49172A87-D932-4875-B00B-07C09A822706}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{8EB13910-E966-4EA5-BF39-E03A200CA0AF}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebMailServerPub
				: orapub-ext01
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{2B9468E6-E8A4-497E-ADF3-0BE4FB2D5AB2}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{232C906D-316B-4650-9334-99C8165EABCC}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http_444
				: http_448
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{245C28D4-9645-4B20-9B4C-F8F74297377B}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-131
			:AdminInfo (
				:chkpf_uid ("{611487E3-C32D-48F6-B3EA-7835950A3E10}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{2F26D3BC-F848-4720-AE28-FA2D81B25843}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{EFADED8C-A61E-47AE-9A0A-791A08210805}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebMailServerPub
				: orapub-ext01
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{E92B3EF6-A0C4-455A-8105-F0E759D83E31}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{1DBC3D44-2ACD-42D4-B7DC-36A95EF3012F}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http_449
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{2B32A023-03F1-462B-BA1A-72402C1B7891}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-132
			:AdminInfo (
				:chkpf_uid ("{B54B4AE7-16F1-4231-AAD0-9362B8209892}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{EFEA4A3F-75B3-490D-B0AE-CA83FEE5AFC8}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{60B4B6CA-90FD-4032-99D7-E84DF8D47EC5}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebMailServerPub
				: orapub-ext01
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{356874D7-0E08-457D-B787-36B90246D938}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{D3EB12B2-ACD4-48BC-B672-B60D6837F08D}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: http_450
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{4596DBCF-C1E0-4768-A099-4AF0846566DE}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-133
			:AdminInfo (
				:chkpf_uid ("{17BFFD96-652F-4694-B865-DCED4A909707}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{474569EE-B57B-4C94-8A87-17DE13C92F67}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{88F2A9C3-EA52-42DC-884C-63B6471B2545}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebProxReve_OTI_NGinfo
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{B1FFE11C-81DC-4EDC-B7E2-F326CB9320A3}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{6907B5C1-9129-465B-A539-B26F739DCE03}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{6166C7FC-046B-4010-95CD-C6D075E5050A}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-134
			:AdminInfo (
				:chkpf_uid ("{55212FE7-A648-4764-8B54-AC550A2AD1DC}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{4EE9E705-5ADC-4BAF-9F4A-16AE0431A728}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{5C1C5ACF-1C84-463D-8FA5-D3EC4E84C5B1}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: smsmt_pub
				: smsmt2_pub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{9B24FFA9-D7C7-4039-8067-6E6C90B213B6}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{0D8E8B88-E199-4E8D-A022-EEACDA3357F6}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{432A7AAB-C757-4413-B0E3-96017E7579CC}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-135
			:AdminInfo (
				:chkpf_uid ("{F9CC062E-C90A-4621-AB4F-F0F4C7C117D3}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{905ABBAE-97B9-42DB-9C1F-B452A4BF10BC}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{4D8223A7-C083-4C20-945D-14199D61F467}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: SRVA007
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{89A65C89-3889-4211-9289-0862C8D10A87}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{B0428743-D10B-40E4-A840-BB7DEBF75174}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{F413EEC0-670C-4A23-9282-6A7C253715B2}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
			)
		)
		: (rule-136
			:AdminInfo (
				:chkpf_uid ("{E1E04F5D-647F-4C9B-A9D1-FBE6E63A3AAF}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{CF2AA315-8374-4F43-A453-4B70998452D1}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{9AE5E59F-9735-4186-BE76-2F45E35FEEEB}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: WebProxRev_test_pub
				: WebProxRev-test-pub1
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{EAB0EA48-F77A-463B-8830-2F47812FB070}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{878F5554-9433-4700-886A-C136C6DCA418}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
				: http_451
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{94407360-FE0B-49B6-A9BB-CE76A168F825}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-137
			:AdminInfo (
				:chkpf_uid ("{FEA092F4-C74A-4F7C-804A-346FB46DF928}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{2CE52979-F07A-4AC9-A92C-FEAB8C01D6C2}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{B9840016-F37D-404A-9E52-81A5BE101E14}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: srv_test_bed_Zebra_pub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{2CDF9EE1-38CD-45D7-BD57-1DC702EE2A4C}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{B911E1D3-8940-4729-A9BD-D4261123FDBC}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{466A6E15-05B3-4794-A521-4ADE1EC84FA2}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-138
			:AdminInfo (
				:chkpf_uid ("{FFAD1ED9-A1B2-46C6-A839-7A6B8C7DA11C}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{7BD0E868-77A5-49CE-9EF8-C54D9E9D13DE}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{9D339B1D-E974-4E23-858F-83EC6C86E2D6}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Srv_Prtg_Pub_Test
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{AA29CA21-51D3-4E92-B625-39313DF59802}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{6A013887-FF07-431A-AD3D-EA18EED43BA2}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
				: icmp-proto
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{648ADFD0-88CF-4ED4-9C34-6380A0742926}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-139
			:AdminInfo (
				:chkpf_uid ("{F9A13952-37C3-4565-9816-4417EECAA1E1}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{6440C22B-0B10-4377-8CFF-55276CE23AEA}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{8EB55FE1-C0E9-4621-BC02-7EB5C712851B}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Srv_New_Zebra_IAH
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{37E072FF-A3B9-471A-9E9A-2F3FDE311F5A}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{542426E8-DD6C-4D62-BE89-5B1C26EA5ECD}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{5E851244-9936-4BB7-9393-A5DEA5F79847}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: ProxyReverse
			)
		)
		: (rule-140
			:AdminInfo (
				:chkpf_uid ("{F9BBD401-D8F1-4CB6-A9AF-835CEFDEF0AB}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{40A9F583-EFFF-40E7-AC86-7CE53841E0CF}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{F2E0CFB4-AEDF-4A76-817B-5D3896DC203D}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: ProxyReverse2_pub
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{1B02F5F1-9CA4-469A-BA11-0EED0EB08767}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{576D14F8-8A09-4644-AB5F-FA344D6A8B2C}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: https
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{BBEA3AA2-896E-4153-BE73-B9D821C5C76F}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-141
			:AdminInfo (
				:chkpf_uid ("{73814D01-3563-4014-944C-E129A50B5F9D}")
				:ClassName (security_rule)
			)
			:action (
				: (accept
					:AdminInfo (
						:chkpf_uid ("{95DC42CA-F606-4409-96D3-90FC28F42235}")
						:ClassName (accept_action)
						:table (setup)
					)
					:action ()
					:macro (RECORD_CONN)
					:type (accept)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{AA7E8F47-AE42-4318-BC2D-2535BBCDDBD3}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: Srv_FTP_DHL
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{FEEBA99D-7BF2-4309-9194-4D47BEC74E53}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{890DC5DB-F997-4578-B7F5-22B6358A29EE}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: ftp
				: icmp-proto
				: ftp-data
				: ftp-port
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{8D344C43-37DD-49CC-97A8-5A8A74D3DA61}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: G_FTP_DHL
			)
		)
		: (rule-142
			:AdminInfo (
				:chkpf_uid ("{35838BEB-C2D9-4471-B543-FB9B8162BA29}")
				:ClassName (security_rule)
			)
			:action (
				: (drop
					:AdminInfo (
						:chkpf_uid ("{B54711F9-7BDA-41CA-82D7-7E5C4599D3FA}")
						:ClassName (drop_action)
						:table (setup)
					)
					:action ()
					:macro ()
					:type (drop)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{21C391C2-C516-40B1-A2EE-9C8418F435F9}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{93E1117B-7751-446C-A32D-029CF842CE80}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{65B2EC5B-471E-4151-9276-8B54732F116C}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{F1FBE387-4783-4FD2-BA86-356F02204502}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: Adresses_Publiques
			)
		)
		: (rule-143
			:AdminInfo (
				:chkpf_uid ("{F10989BA-5EBE-4B82-B989-6D8164FD238F}")
				:ClassName (security_rule)
			)
			:action (
				: (drop
					:AdminInfo (
						:chkpf_uid ("{E5D17BCF-F92F-4A05-BE98-B92C38549B5D}")
						:ClassName (drop_action)
						:table (setup)
					)
					:action ()
					:macro ()
					:type (drop)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: None
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{D2A246F3-564E-4E0A-89EE-B2812F381AEB}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{D7CA2434-97DC-4FBE-9F48-9883DCE70F28}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{6F017697-DFFE-40E8-AE41-79BE769619BE}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: dns
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{26B3CEA4-AEFD-4AA1-9676-68061C209252}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: srvb005
				: srvB003
				: SRVE001
			)
		)
		: (rule-144
			:AdminInfo (
				:chkpf_uid ("{F4712C1E-27CC-449D-91F5-14701AEEAC78}")
				:ClassName (security_rule)
			)
			:action (
				: (drop
					:AdminInfo (
						:chkpf_uid ("{9BC16BEB-1BE7-4BAB-963B-374FED469E3F}")
						:ClassName (drop_action)
						:table (setup)
					)
					:action ()
					:macro ()
					:type (drop)
				)
			)
			:disabled (false)
			:global_location (middle)
			:through (
				: (ReferenceObject
					:Name (Any)
					:Table (globals)
					:Uid ("{97AEB369-9AEA-11D5-BD16-0090272CCB30}")
				)
			)
			:time (
				: (Any
					:color (Blue)
				)
			)
			:track (
				: Log
			)
			:dst (
				:AdminInfo (
					:chkpf_uid ("{A0A6E181-73DA-417A-BA99-9D7934EFAF80}")
					:ClassName (rule_destination)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:install (
				:AdminInfo (
					:chkpf_uid ("{0DB47271-3EC4-4BA2-A809-262375C9E944}")
					:ClassName (rule_install)
				)
				:compound ()
				: Fwent
			)
			:services (
				:AdminInfo (
					:chkpf_uid ("{218634AF-318C-46D5-B15B-FCCF9F76E146}")
					:ClassName (rule_services)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
			:src (
				:AdminInfo (
					:chkpf_uid ("{A932AD41-76D7-41E6-B336-5BDEF239AB56}")
					:ClassName (rule_source)
				)
				:compound ()
				:op ()
				: (Any
					:color (Blue)
				)
			)
		)
	)
	:rules-adtr (
		: (rule-1
			:AdminInfo (
				:chkpf_uid ("{841417DB-04DA-4136-A519-4535E7B8C7D7}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_Pase_relais_entreprise
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DSI_sadm_BZR
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6D723E03-DD53-468D-A5D0-9C08F6BECF4E}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{ADA84C4C-693D-48BD-886D-52DDB6BBF3C9}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C500F737-D420-4F4D-BBEA-9ACC2390B00A}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-2
			:AdminInfo (
				:chkpf_uid ("{042DFBC8-F0D6-48FD-A573-FFABF30B9824}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Pool_OMA
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_192.168.253.0
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{4FDCD8DA-281C-452F-995D-98ED6526D7FB}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C01B4193-068B-4780-8164-FAED26E6D72A}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C4131593-5888-4C48-BE66-4D6615568AC3}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-3
			:AdminInfo (
				:chkpf_uid ("{55E37A1E-0DBC-4B2A-A64F-EEAAB0C7969F}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_Pase_relais_entreprise
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Smokeping-interne
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{89C233A3-A020-47CE-BFB0-370A286C3B0F}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E0AAAFEC-7B48-4AD4-84CF-54EB3E8D683D}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{A3F91726-3BF3-4D43-B53C-38A066CB7AAB}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-4
			:AdminInfo (
				:chkpf_uid ("{B84BFFEC-662C-4703-A1FA-379B872FA5D3}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: VLAN_DMZ_Serv_Appli
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Smokeping-interne
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{40FB1FEA-8C78-4E44-8400-80455EA4630E}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C971CD30-74FD-484B-B556-E8E5D46D4405}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D865C965-19EB-4862-AC19-E9F56887ADB6}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-5
			:AdminInfo (
				:chkpf_uid ("{841417DB-04DA-4136-A519-4535E7B8C7D7}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: DNS1_OMA
			)
			:global_location (middle)
			:install (
				: (Any
					:color (Blue)
				)
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: srvB003
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F0B0FC22-5F0A-4968-943A-FDC9AE3AFD80}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{52253709-B424-4D3E-B9A4-27D49F6F8EE5}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8707A4BB-F171-4CCD-8A79-545E6EFA8936}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: orapub-int01
			)
		)
		: (rule-6
			:AdminInfo (
				:chkpf_uid ("{7B0CBE57-11F3-47E0-B124-314E2143986C}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: DNS2_OMA
			)
			:global_location (middle)
			:install (
				: (Any
					:color (Blue)
				)
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: srvB003
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0F390134-C5B3-419F-A20F-D0C7C7A83E08}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6CC2B233-63FD-4ED0-B5DC-84F55B8B0AFC}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{EDCFE1DB-BF30-4441-BC01-6F3797DCD859}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: orapub-int01
			)
		)
		: (rule-7
			:AdminInfo (
				:chkpf_uid ("{8F9EA046-D65A-4AF3-A1FC-2BD74CC4EDB3}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: DNS1_OMA
			)
			:global_location (middle)
			:install (
				: (Any
					:color (Blue)
				)
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: srvb005
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{40E568CC-4E04-4E70-A279-9A0F52A71780}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0885F10D-C933-440A-94E1-596E545780D8}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3458EF6E-D73F-4659-8A0A-6D753D612226}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: orapub-int01
			)
		)
		: (rule-8
			:AdminInfo (
				:chkpf_uid ("{9E9BE371-F7E6-437D-A11A-B3632DAAF989}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: DNS2_OMA
			)
			:global_location (middle)
			:install (
				: (Any
					:color (Blue)
				)
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: srvb005
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{DAE5518F-903A-4584-933C-8A179897D8B2}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F8585BA8-534D-4199-BCBB-E21931AC3515}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B79E366B-D835-4E81-9D78-5B7AC22FCAA8}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: orapub-int01
			)
		)
		: (rule-10
			:AdminInfo (
				:chkpf_uid ("{270F027C-460C-4193-ACA0-EEA1A96D09CE}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_Consultants_25
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{ECAF3342-23A0-4BBF-A679-1CBEE43E795D}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{66512F5C-4478-4AF7-AF31-AEFDDB9ECF66}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B4F5A887-6688-4D97-88F1-A5F16A07766B}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-11
			:AdminInfo (
				:chkpf_uid ("{66108332-4E29-495E-9190-B1C6E1E6B732}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8812DDFB-017D-4E60-A9D5-24325AB38D23}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{91A1608E-9374-43B5-84DC-C7BB5619D998}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0EB7C3D3-1E69-4C39-81A8-80F59EFA20D0}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-12
			:AdminInfo (
				:chkpf_uid ("{C6C206F0-D34F-46CB-ADC6-1B5A74267827}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Gr_Subnet_Skill_Soft
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B6E664B7-0E6B-4063-BBEA-75C5D00DC35D}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{21E4A880-716C-41BB-AB47-78FAD4D55421}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E620FE47-154F-4A06-ACDA-43CE42494A7E}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-13
			:AdminInfo (
				:chkpf_uid ("{94BAECCB-984C-4B00-8493-8C848494885F}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Srv_Portail_oma_fe2
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{93892731-D532-4214-9D41-7288495CD19E}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{49EEA5A8-DB41-4938-AA05-515A2EC833EA}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{31A70A98-A504-4043-87DF-6BFA51C4A44B}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-14
			:AdminInfo (
				:chkpf_uid ("{841417DB-04DA-4136-A519-4535E7B8C7D7}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Gr_SKILLPORT.COM
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{263347C1-EEAD-4845-BEC3-1FE13BB2A6DF}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F93C3620-BA3D-4E5C-8987-74128C374231}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{BEB9A5C7-9DCD-4AC3-B138-03A89B521F6C}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-15
			:AdminInfo (
				:chkpf_uid ("{841417DB-04DA-4136-A519-4535E7B8C7D7}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: orapub-int01
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Eyes_Of_Network
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9643BD6B-A1E4-477D-B7C7-6ED91CFFC1B7}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: orapub-int01
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0419D093-C32F-4082-936A-98C4DFF4AE90}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{A5E88B26-919B-4380-8721-77714F7AE37C}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-16
			:AdminInfo (
				:chkpf_uid ("{41339916-6C58-42B1-9D67-C6ED33A1A090}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: PC_Pierrre_Alain
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{959F429D-B0FC-48C8-845E-841798DE2DDD}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C9A6DC6A-62BD-441A-9B69-B808DDCBFD00}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{A46E14C5-476D-4F8B-91C3-29C3FC46D2C1}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: orapub-int01
			)
		)
		: (rule-17
			:AdminInfo (
				:chkpf_uid ("{841417DB-04DA-4136-A519-4535E7B8C7D7}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Srv_ip_SMTP_pub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{7AA48074-DE18-49BB-8FE3-5AE6D9797002}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B2D60284-D785-4AD3-BD30-0AA37E8FDB70}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{28644312-1CD3-43CF-9B2C-8525544CFD24}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-18
			:AdminInfo (
				:chkpf_uid ("{5388D1C6-29C2-4AE4-B5A5-D117BA1C89FC}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Srv_Proxy_Rev_27_ISP
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6B1A36F8-6EE5-4B0F-AA60-1831DD9A5800}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C0881065-4493-497E-9EEC-2304C5036D85}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{224A4846-BE48-4E7B-ADE4-F282FA28B2B6}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-19
			:AdminInfo (
				:chkpf_uid ("{CC254D6E-278C-434F-B975-D64F610FAEF2}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Srv_Proxy_Rev_30_ISP
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{278A3AF2-6DA8-4EAE-8A36-49871413D724}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8E5E9894-02FD-49DC-8F6B-5C66A1CF2713}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{DC3B478B-28CA-443E-9BF9-73590CCBC147}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-20
			:AdminInfo (
				:chkpf_uid ("{1706FB99-D1A9-4CD5-95B8-792C5D4A142D}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: NS5GT_pub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Fw_Alcatel_RAMSES_Flows
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2C9AC8C3-62B7-4F94-8007-5AA71901F02A}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: IN_NS5GT_priv
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6076EAC9-9CA5-43EC-92E5-867C4A21F65C}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{BE058439-630B-4C42-A8EB-301B9EECAED0}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-21
			:AdminInfo (
				:chkpf_uid ("{87425212-6013-46C9-9359-83F35E43AD15}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: (Any
					:color (Blue)
				)
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FCA213F4-E269-4763-ACA4-346C96161C9A}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9A1C931E-84D1-4D05-B915-B5C9498D355C}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3B66C93A-1DFC-42F9-95BB-9463A923310F}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-22
			:AdminInfo (
				:chkpf_uid ("{841417DB-04DA-4136-A519-4535E7B8C7D7}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_PASES
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9E236678-DB10-459A-B7DB-C9414BC1A5E4}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E4E98C9F-B1B8-421A-859D-4A6909041EA5}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{A1D09804-9374-4853-8F81-152DD4D9F681}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-23
			:AdminInfo (
				:chkpf_uid ("{EFDEC7A0-9570-4760-A195-192A5A3FFFCE}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_New_Noc_ISP
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B4A100E6-ED8A-4B58-872C-FAF2178558ED}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0AD7654A-7094-4450-A987-F34FE08DBA3C}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8B3AE0D4-DECC-4DCC-AC47-CB982AF5EDB3}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-24
			:AdminInfo (
				:chkpf_uid ("{B440E6E3-4C67-4F02-BE44-5A604C369542}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_SI_OMG
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_PASES
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{7DC28B12-A3D1-4468-9FBF-71B1F7920737}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{CC3D71EC-6A35-4B92-9493-3F218B54EBAB}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{03D3675B-5F18-4019-86AB-8339800378FA}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-25
			:AdminInfo (
				:chkpf_uid ("{93B8DBBE-AD1D-462B-9A64-D86C53E5C8F1}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: G_remote_pop_smtp_orangenet
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: smtp
			)
			:src_adtr (
				: Net_Clients_23high
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FDB56CC1-4C3A-42F9-834A-A07DE95A0583}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{74C0B187-7191-46ED-AB6E-52C23A025DA0}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{45F2B76D-10F9-495E-BFDF-D158199CADD0}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-26
			:AdminInfo (
				:chkpf_uid ("{574E2F5F-E8B0-48ED-9E4D-D6B4A9781451}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: G_remote_pop_smtp_orangenet
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: pop-3
			)
			:src_adtr (
				: Net_Clients_23high
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{4DE4D373-17ED-4802-864E-9CF195A0DE4D}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E3472D9E-AA1B-424A-9B36-2C49DA261BF7}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8C2D125E-98AD-4FF2-927F-6C6F74AA5589}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-27
			:AdminInfo (
				:chkpf_uid ("{D92F1D6C-F758-48E9-8E8A-2F94C20F3EB7}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: proxent1
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C44D5A14-275A-4A68-8931-95A1D08C2EF6}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{084E6C6F-FAC7-4398-87BA-71737342D562}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{56386AA1-986E-45BC-966D-885BE324DE4D}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-28
			:AdminInfo (
				:chkpf_uid ("{6F62FDD6-89F2-4200-982B-68FA3E5CCE71}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: proxyISA1
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{32B291F2-BFE3-466B-B785-A9EDFC9B8F49}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{68EEB855-C5A2-4C36-999F-9573E1C8CACF}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{EA255DB0-1414-48CB-83A7-FCEBE2E857EA}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-29
			:AdminInfo (
				:chkpf_uid ("{365A9BBB-4D63-4151-929E-449035950705}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: ProxyISA2
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{EC496374-1C96-4454-B080-BEB9A8D57A82}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{1F2FA74E-1F5D-4142-95F2-180C7E256019}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F9F46650-030F-47E6-8660-C6148FD78182}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-30
			:AdminInfo (
				:chkpf_uid ("{41CAF9E8-2BEC-4AE1-B32F-9F8C101EB12B}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: srv_ftp_local_3g
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D5B96B00-778F-40C6-B310-344F5ACC91C4}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{7D1C5FC7-0E9A-4B8C-BD72-A88DDEABCD3B}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{578C505D-B420-4319-8784-AB8E08A4804F}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-31
			:AdminInfo (
				:chkpf_uid ("{822E45EA-8719-4A5F-94D8-ECAFD360E401}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Srv_New_NTPINTERNE
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{1B063574-9F13-4A05-A446-3A4B4B6D54B6}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C1CEF6E7-F8DD-4458-9275-97598B18F820}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{A0094471-F151-48A4-9447-95B17E04E04B}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-32
			:AdminInfo (
				:chkpf_uid ("{06F3F031-F4BB-494F-82AF-3DA2B9F315FF}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: NTP_OLEANET_NET
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: ntpi1interne
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{CEBC4131-B405-455E-8DD5-143AACE7D5A5}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0A417B75-B287-434D-9989-3D9A51485DCF}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{576AEAA6-F41B-488C-AA52-3B5F4C280D87}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-33
			:AdminInfo (
				:chkpf_uid ("{5C8A2469-A979-49AA-86D6-0451209A8998}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: NTP_OLEANET_NET
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: ntp
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{53C6B492-D465-4753-85E1-EA414040176F}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E94C4C72-6088-45D6-B322-9DF7BA4E9C16}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F3E207C4-4FCD-46F4-8492-AB04940AFBC0}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-34
			:AdminInfo (
				:chkpf_uid ("{6576BC62-0AF4-4525-A8D1-C648A226D6B4}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: PushMail-provisionning
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{285F1193-15F5-4E66-9403-DE91ADC49653}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0D26C940-A807-424E-812C-C25346AC32EE}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{906A4184-8FCD-45F6-8935-66BB66D4A394}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-35
			:AdminInfo (
				:chkpf_uid ("{AF69D66D-0277-4F60-BDE1-66F629E267AB}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: PushMail-provisionning
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: https
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{7F539EDC-824A-4898-AEF6-7F5E304B1391}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D74D7D5B-89F3-4BD6-87A0-281D872AFA3E}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C87D5DDA-AEDD-42ED-9D48-6F474D21468A}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-36
			:AdminInfo (
				:chkpf_uid ("{221129CA-9D7D-4F94-BD65-2515FABA01C7}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: dns
			)
			:src_adtr (
				: ntpi1interne
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{CED6D8F3-7D4E-47F1-BEAA-AFB524D0A3D7}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C6851295-C21B-4A0E-9799-9A3E069FC40B}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{435AA4DA-539D-4D25-B85C-6F2E56AD4BA6}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-37
			:AdminInfo (
				:chkpf_uid ("{9D4CCB30-BCD6-48A2-A27B-05012213D373}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: G_srv_DNS
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: dns
			)
			:src_adtr (
				: fwmgr
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{EB4FD590-6E46-4603-A701-E061C1E75FFE}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3AFDA87F-31D3-4623-B0C1-F414A8FEF721}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{12F52875-64F3-445A-9E92-5FBE53B4DF5E}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-38
			:AdminInfo (
				:chkpf_uid ("{71788005-C077-4BD7-A796-6D3549A73FD7}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: G_srv_DNS
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: dns
			)
			:src_adtr (
				: ProxyISA
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{62708808-FEC1-4ECB-962F-6A3F10859582}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{05511554-D1E1-4011-B64E-51F20DF38301}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{741CAF87-E32C-49F7-A0C0-08009CB1487C}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-39
			:AdminInfo (
				:chkpf_uid ("{5A88B680-FF75-4118-912D-ADA94A8262EB}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebRadioPub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: tcp601x_webradio
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{303739F4-5C3E-44A4-B2D3-37AA038B681B}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: srv_sva_dartagnan
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{82D2138F-9302-49D5-904E-4FDA47F16640}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E9F93924-7E32-46D6-B521-0D0236CEABFB}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-40
			:AdminInfo (
				:chkpf_uid ("{E287E9F3-23F9-4689-B19C-EB473409F69E}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_Agences_Minilink
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Smokeping-interne
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5BB0DFB3-CF95-411D-9E21-EEDCAB709C63}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{58074A8F-F0D6-4250-8D51-A46DFA2E8DF5}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{44AE2023-4192-4C66-9C19-72D95A43C6D6}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-41
			:AdminInfo (
				:chkpf_uid ("{B695824E-930D-42D2-AFC1-B3630EB7206C}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Smokeping-interne
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{022F96B8-0B1D-41DD-B276-09EA76E57B57}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{139CD645-C447-47C3-A226-721ED157E3A4}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{1078EC4B-4E20-4398-BFAD-E991F1D407F4}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-42
			:AdminInfo (
				:chkpf_uid ("{417D2CAE-1955-40E5-BB5C-C507FFA3C8DC}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: srv_test_nagios
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{DFEED128-E455-4CE2-BFF8-6F6308C4AE81}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{91BA0EA9-09D5-49E4-840B-CAA26D9C02F0}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{65D74833-4FB4-408E-AF77-1E2CE5ECB492}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-43
			:AdminInfo (
				:chkpf_uid ("{1CC56997-6832-42C8-BF9A-65AF9E9DC5BB}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: SRVBLB
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2BFBF7AE-F561-4204-81CF-9DD51CB1CC7C}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{305C9873-682E-452B-85EB-675744E57832}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{CF1ACF9C-06EF-4918-8034-297FB686D5B8}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-44
			:AdminInfo (
				:chkpf_uid ("{DB8A9F3B-64B7-4526-9C5A-393E08DBD790}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: srv_test_BES_EX
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E2ACCEA5-BA79-457D-8008-CD01B5373445}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{67ADCEF1-4653-4887-A53C-9136BA95E54B}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{164EDC59-B3FE-488D-9BBD-8A5A908D2301}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-45
			:AdminInfo (
				:chkpf_uid ("{B1E589EF-D3ED-4F14-BE95-725F973C7BA3}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Srv_PreProd_BES_EX
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{73FD3D75-3D4D-4BDF-8637-2A8EE92EE7B9}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{401DBD3F-3917-4899-96AD-734BBC72B8ED}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2A822E15-10A5-4BED-BE3B-DC144D9EEC51}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-47
			:AdminInfo (
				:chkpf_uid ("{180621F8-92BB-42AB-B462-E8D5364020D6}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: srv_exchange_test_bes
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FA65832F-50FF-4BA1-8DA8-487FBA0828D8}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E50C66C8-6EC2-435C-9721-83BE00559565}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0DE14AE8-3922-43DE-8B41-E5E9253F4A66}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-48
			:AdminInfo (
				:chkpf_uid ("{005B998F-890F-45ED-ACAB-3C2ACA9582A1}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: ntpi1interne
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{EEFE8011-EBF0-492B-A69D-9B8FD7DADEE4}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{43374B9C-A000-4401-9087-33C54E3B0603}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{A5905829-C092-4682-956C-517C28CE6FCC}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-49
			:AdminInfo (
				:chkpf_uid ("{42221D8E-9F7C-45E5-A154-95C6C4F4896B}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: PC_test_supervision
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C8FA4B66-C77F-484D-ACE6-647C56895714}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3FDA8732-72DB-4A88-871C-D5586BAE4CBA}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{89D6B89D-0A40-4425-BB49-50E26EAC6E60}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-50
			:AdminInfo (
				:chkpf_uid ("{F45B8CA6-E8FB-4C4A-83B3-21F02A957170}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Proxy2pub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{93F6B0DF-D502-4796-91D5-C105DE159A99}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ntpi1interne
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5E2B1898-0B7B-4D98-A10A-C98B1694C9D1}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{4DF5BE00-88B3-474E-8A4C-0C3BBF2CBE79}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-51
			:AdminInfo (
				:chkpf_uid ("{17CF0623-C487-4163-9DAB-08FC0909E3C1}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: POP3_HIDE
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Temp_RemoteCecosane
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{83FEC644-31E6-44BD-A9D2-C68DDF435C83}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: srvCecosane
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0B07FCE7-D373-4073-9D00-CCB32DFDBCF9}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0A79AB5F-E185-466D-ABD0-6094503F5583}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-52
			:AdminInfo (
				:chkpf_uid ("{6C3D7C75-6DEE-4409-A172-16272A228F31}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Group_mach
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: proxyISA1
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2EB57231-F69E-434C-BB7D-7FF6083D0A1D}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{99F4A7BF-8090-4857-AD12-8BCA5830A6DA}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{900FAC9D-5588-4218-95AC-D7CE220B8AD2}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: onilahy_pub
			)
		)
		: (rule-53
			:AdminInfo (
				:chkpf_uid ("{B627A86B-7648-4787-908D-ADB7DDA68C7D}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Group_mach
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: ProxyISA2
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{166E2134-CAAD-4D21-B000-553BA1C74B8F}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D008994B-CB35-403A-932C-3C79B68824CC}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{AFEC6FF3-6CCA-449C-9572-2C5E5ADFC14A}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: onilahy_pub
			)
		)
		: (rule-54
			:AdminInfo (
				:chkpf_uid ("{19F0AB07-FD22-4291-868F-EE9CC1B01FA4}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: onilahy_pub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Group_mach
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{20CDC5ED-9252-4469-99A4-455E2297BC0D}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: Srv_Si_Onibe
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{14EECEBE-1235-4EAE-9862-2AEFAF453486}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{ABF287E8-42AE-499C-A6F1-7A4EEA340771}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-55
			:AdminInfo (
				:chkpf_uid ("{25E00274-7E8B-4E17-913C-4ED8629462B2}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Ferma_PSI11_NAT
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Fw_Ferma_Flows
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C5D60AD7-2C6D-4998-B281-F45FFBDD2B70}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: Ferma_PSI11
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{15C59CE8-2B98-48F5-A643-069181B362DE}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{97BDD70E-E530-4C54-85C0-3A2A31A7F281}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-56
			:AdminInfo (
				:chkpf_uid ("{2EDDEE61-5262-4363-9786-43C75D3D27E6}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Ferma_Web_MSD_NAT
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Fw_Ferma_Flows
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{DED4CA7D-B5BA-47C1-994E-DAE5BB566666}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: FERMA_pub-zmsd1
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{1F918326-E97C-4A19-9F73-589966049CF7}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{64947A42-1D59-453E-B724-C01FC575B6C0}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-58
			:AdminInfo (
				:chkpf_uid ("{AA8047E8-B49D-46F2-BDCE-FA1F19178D23}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Ferma_PSI12_NAT
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Fw_Ferma_Flows
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5409775A-CCE7-4422-BB3C-B6A15F38B745}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: Ferma_pub-lanco
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3521B357-1E4A-4941-9C00-647B81BDD65D}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{289FA28F-4D34-422E-B700-F21BB0716579}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-59
			:AdminInfo (
				:chkpf_uid ("{1F949D9D-1CF2-4233-B7EE-6F76F95CED81}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Fw_Ferma_Flows
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Ferma_PSI11
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{050C64B3-4DB7-46A1-A2F6-A754BE0AAF8E}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C0244D70-F68B-4481-8D57-014ED3CDD39E}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6CE4B8EB-5947-44B7-ACEF-B56C391D0B55}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: Ferma_PSI12_NAT
			)
		)
		: (rule-60
			:AdminInfo (
				:chkpf_uid ("{E9D0D725-B702-4E3B-A4BF-3C454EDD4F0D}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Peer_Roscom_Host1
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Roscom_DSI
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D21D8FA7-9294-463C-A337-F0D90F1E86CB}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8903A5D4-6194-4333-8F1E-745F4A32CFC6}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FF9E38EC-68C3-41A2-AA87-52947F655C47}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: Roscom_DSI_NAT
			)
		)
		: (rule-61
			:AdminInfo (
				:chkpf_uid ("{0A14D812-0D40-4DEF-B04A-E7662C8C2E5C}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Roscom_DSI_NAT
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Peer_Roscom_Host1
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{657665CC-911B-48C0-835D-83D8B43F72EB}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: Roscom_DSI
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5022CA7F-6B1C-4CCC-9BB5-D887B10B8BBF}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6899B3B5-C2FA-43CF-9A54-9EBFE4DAE756}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-62
			:AdminInfo (
				:chkpf_uid ("{906949DC-9F0C-4C32-B3F9-5D3F8D273C4B}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_Routeur_AGences
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DSI_sadm_BZR
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{53EB01BF-D5B8-4EE5-80AC-0AE45675E4C5}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5ACECC9F-0F90-4112-AC77-813183DBE7BD}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5BB14740-4853-4135-A62A-794FD8FA4E67}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-63
			:AdminInfo (
				:chkpf_uid ("{ED05F8D8-BA1E-408F-8DDC-2CD3951EB652}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DSI_sadm_BZR
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{00A9AEC7-4CB3-4AD9-B2F1-9BD12B310FEF}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B6F65EC7-80AB-4332-A27A-40F4700C8EDE}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{21A41F93-F7EF-4D33-A90A-FCB5A4D9A055}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-64
			:AdminInfo (
				:chkpf_uid ("{6A6C217E-9CD2-47DF-A25C-31A522592714}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Srv_New_Zebra_IAH
			)
			:global_location (middle)
			:install (
				: (Any
					:color (Blue)
				)
			)
			:rule_block_number (1)
			:services_adtr (
				: https
			)
			:src_adtr (
				: ProxyReverse
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5C358700-EAD3-4F52-84AB-B03F84D46D44}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8D995DBB-E61B-4367-8436-B1C69286E92D}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{7F497E9A-7C79-4231-8C2D-6EB1ABC5E62B}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: WebMailServerPub
			)
		)
		: (rule-65
			:AdminInfo (
				:chkpf_uid ("{30CBFFC2-3019-4531-AACC-D48438325B80}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebRadioPub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: RAdmin
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6159E317-E024-4A6A-AC01-0F4A807EBC17}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: srv_sva_dartagnan
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C3F17FCC-3C89-4A4F-9FB4-65CD843D08F4}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{31D69BFF-68A4-44ED-8D2F-957A31A0C723}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-66
			:AdminInfo (
				:chkpf_uid ("{01EF4589-8956-4EED-827E-12CB8A7DD1ED}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebRadioPub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: tcp601x_webradio
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C7A3A1D8-9980-477F-876E-CBAF329C306A}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: srv_sva_dartagnan
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9528F9E0-F43D-4203-BC4A-CF5E3D90F0A9}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8E0A2C6B-5812-4435-8087-3FCA340C25EF}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-67
			:AdminInfo (
				:chkpf_uid ("{6FDE6429-3356-49AE-8152-0A18B67D7FEE}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebRadioPub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: udp601x_WebRadio
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D3F78B6D-C331-42A9-9787-B8E2454AE04E}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: srv_sva_dartagnan
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0552265E-DB98-4700-B23F-586E3283DC01}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9356F559-D982-4910-9618-219D6C6E0DA9}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-68
			:AdminInfo (
				:chkpf_uid ("{E2ECCEF3-7017-4CBE-AE9E-07A67FD8A03D}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebRadioPub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: WebRadio_streamer
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{4CBFF276-B8A0-490E-AFDD-8072DCDE511A}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: srv_sva_dartagnan
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F3FC1CBF-407E-4DC0-BFB4-3E69EC9A7132}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D918CFC4-F8DE-48A7-86FF-206ABC46F24F}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-69
			:AdminInfo (
				:chkpf_uid ("{97BFE2ED-B83F-4789-AB06-D3FC316BB72A}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebRadio_streamer
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: srv_sva_dartagnan
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{85FEA5B7-A861-4658-AFBD-B41A3D7E4331}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{1AD05251-DB04-4C91-802C-12F6CA18EE86}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F80DE260-5AC9-4AB8-8438-5CA104536F16}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: WebRadioPub
			)
		)
		: (rule-70
			:AdminInfo (
				:chkpf_uid ("{7D45D128-5880-464A-9AB6-4D4D64F421D1}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebRadio_Admin2
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: srv_sva_dartagnan
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{CF6F11B0-EFDF-4200-8BBE-4E4F5CA4B9B0}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C4CCB429-548D-4A1D-935E-D597B85DCD39}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{DF0128FC-8DE0-4D9C-B2AA-4D9BD62C98BF}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: WebRadioPub
			)
		)
		: (rule-71
			:AdminInfo (
				:chkpf_uid ("{1F904EBB-EF00-4855-83B0-A325F29543B1}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebRadio_mp3_multicast
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: srv_sva_dartagnan
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{AB1F8803-0C91-4AD8-90EF-52E203DC4E81}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{416BC0FA-B26C-44FF-891C-31558B7D2791}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{DE424A7A-EDA9-458A-99E1-02FF8F90F870}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: WebRadioPub
			)
		)
		: (rule-72
			:AdminInfo (
				:chkpf_uid ("{37F134E7-E30E-41A4-8D1E-55C869C9F806}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: G_srv_DNS
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: dns
			)
			:src_adtr (
				: srv_sva_dartagnan
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{49228F7D-B3EE-4D56-8591-380C9003A4FC}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{74179F9E-A4A2-43B5-8725-CCF8C640EF8C}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E09FD3A1-033F-42B5-85BD-40056C07AF69}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: WebRadioPub
			)
		)
		: (rule-73
			:AdminInfo (
				:chkpf_uid ("{7B017795-B321-439A-93F9-C068127B6AB3}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: tcp8001
			)
			:src_adtr (
				: srv_sva_dartagnan
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{50BE9BC2-4FAA-49BA-A38A-26213C2F3BE0}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FC3205DA-EB22-465F-91BE-EEEEE73F8FE1}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{38C104F2-CFAA-4F76-AC51-2C6373FCEBD3}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: WebRadioPub
			)
		)
		: (rule-74
			:AdminInfo (
				:chkpf_uid ("{A4E16D2D-FCB9-4178-8957-423E467AC7DF}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http_8000
			)
			:src_adtr (
				: srv_sva_dartagnan
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3AFCEEBD-101E-47AF-BC21-ECDB8C233B7E}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{EB570FC9-710B-49C6-BFF9-F05E89D31820}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0E977551-18AA-4C91-AE12-7AB43542A2D8}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: WebRadioPub
			)
		)
		: (rule-75
			:AdminInfo (
				:chkpf_uid ("{398816B2-74A9-4605-9042-B3E044927654}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: ntp
			)
			:src_adtr (
				: srv_sva_dartagnan
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{A6D02D64-760D-45F7-A54C-E028255B03BC}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9CAF230E-7E86-4FA2-B32E-F53240F55473}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{14DD16F1-0CDE-4CB6-AA18-46CA1F4DFF53}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: WebRadioPub
			)
		)
		: (rule-76
			:AdminInfo (
				:chkpf_uid ("{362F80E1-1045-460E-B6C3-48F35F3EEDED}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: G_srv_DNS
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: G_srv_prTech
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{35F55F3D-1E81-41BF-8DAF-BA3E0C44F6DD}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{AF7D7071-3C73-48F2-A9D7-1C3B04704A48}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{847C5E5E-6804-4E9B-911F-9FE2B96E1F28}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: Srv_prtech_pub_SmsPlus
			)
		)
		: (rule-77
			:AdminInfo (
				:chkpf_uid ("{0D2F0F9F-46AB-4520-82C6-4BD61C1F3DCA}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Site_RUN_SMS_FR
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: G_srv_prTech
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5B359132-AAA8-4CD5-BCC4-9F9D3779EC1B}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3389A5B6-3EBE-4BC4-A697-F246A6C7E648}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FB664D26-2A8A-4776-BEEA-F56CCDF0D027}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: Srv_prtech_pub_SmsPlus
			)
		)
		: (rule-78
			:AdminInfo (
				:chkpf_uid ("{8E10E9F3-5B9C-40D4-ABE2-586A752C5412}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Site_ftp_clients_afp_com
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: G_srv_prTech
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FA25E4A0-24FD-4812-AB30-C56766815F21}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C458F4F7-9C85-4BDE-AE13-D1DEE36F04FD}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FBA8AA49-29E0-4B7C-85CE-D57AA7145C2A}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: Srv_prtech_pub_SmsPlus
			)
		)
		: (rule-79
			:AdminInfo (
				:chkpf_uid ("{8D79E56D-93BE-44C7-9D6A-AE867ED8FF3D}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Site_ftp_cpth_ie
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: G_srv_prTech
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F6F5DF5B-D85D-4055-9750-7493AA4FE085}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{09F0E5BF-A464-46FA-B706-2872977A5E3C}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{78B3B4E3-9B8B-4367-8DEA-DAF7512C2EE8}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: Srv_prtech_pub_SmsPlus
			)
		)
		: (rule-80
			:AdminInfo (
				:chkpf_uid ("{806E85F7-E9F3-41EE-B0A2-B5B708BBF7D3}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: PushMail-provisionning
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: G_srv_prTech
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{288B9610-885D-4FB9-A281-ED16EE5D63B2}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B0430D61-02C4-4712-A54D-7F995E664B21}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9F7DAD50-6A0C-4229-9CDF-48F47CF4E4E5}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: Srv_prtech_pub_SmsPlus
			)
		)
		: (rule-82
			:AdminInfo (
				:chkpf_uid ("{54BCF819-D9FC-4C6F-8F0A-3D27921C3CED}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Srv_prtech_pub_SmsPlus
			)
			:global_location (middle)
			:install (
				: (Any
					:color (Blue)
				)
			)
			:rule_block_number (1)
			:services_adtr (
				: http_9080
			)
			:src_adtr (
				: Srv_test_Coralys
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6D4300B6-4164-4BA9-BBFE-DA9F85C45A4D}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: srv_prTech02
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0DAAFB65-D44F-4094-BAA5-60DDE7E3B0FC}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{4275F8E4-55C1-4313-B442-0B70D0994FEA}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-83
			:AdminInfo (
				:chkpf_uid ("{81819D91-311B-436E-B09F-7152D3549516}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: HttpPortal_pub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0F5E1812-1597-49CE-A4EE-B7611737FF5B}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: HttpPortal
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6E169115-9DE0-4C03-A820-226FE79B1F31}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9DE25F1F-79B4-4BD9-94B0-9E54D3525C06}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-84
			:AdminInfo (
				:chkpf_uid ("{DF98C416-80BE-49E2-A0E4-ED0D4F342A56}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: HttpPortal_pub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: WebRadio_webportalContentUploader
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2956B464-3335-4A14-BF29-345888449E18}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: HttpPortal
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B5A76C26-D821-47CE-9085-5C0315006BFD}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B499BB9C-499B-4888-A8A1-35E0E0108BE3}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-85
			:AdminInfo (
				:chkpf_uid ("{114CCF94-B633-4BFA-BFAA-5F00C6C69E70}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: HttpPortal_pub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Remote_Backteam
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B8A42A71-916A-4EB4-80D1-E1BE3EAB18F5}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: HttpPortal
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5B36D502-67B0-4094-97AC-07A1002FFC26}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2132AB2E-87DB-48D2-ADAD-46E9EBF8D4B0}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-86
			:AdminInfo (
				:chkpf_uid ("{3ACDCB6B-EA97-442E-88DC-B52CCBF45790}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: HttpPortal_pub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Remote_Backteam_1
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{BC4B31C9-02CE-48FE-A1FE-6FE49F189CE3}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: HttpPortal
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{4F01AA68-3EEC-4C51-9F5C-F620517743C6}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0C994D6F-4638-4B77-8BC4-42D7E00614DB}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-87
			:AdminInfo (
				:chkpf_uid ("{5A5A7B5A-6BE3-4470-BAEA-CD4BC668E19E}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: G_srv_DNS
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: HttpPortal
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C3454EF2-CD3E-4280-9A09-3B80D872DF21}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{32C3C718-DE98-44F5-9420-5057F2136FA8}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FDBB99BC-A688-4EEE-B6A7-CAC6FE45817C}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: HttpPortal_pub
			)
		)
		: (rule-88
			:AdminInfo (
				:chkpf_uid ("{876546AA-8BAD-4912-B567-40E1CD5AFA53}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: DNS1_OMA
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: HttpPortal
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B3431646-C9E7-4A37-A96F-1EC9EF7714D9}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{208E3C7D-1C78-4B3E-87EB-C912CF607999}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{04D64B3D-F7C7-4603-824B-A87D391FD479}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: HttpPortal_pub
			)
		)
		: (rule-89
			:AdminInfo (
				:chkpf_uid ("{5747FC69-DD02-49C1-92F3-4646DB11E445}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_portail_bacc_privee
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: HttpPortal
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{1B431004-338F-455E-A1B2-A1C7410D8599}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FD49DAE2-1235-4276-8144-C8D19C334530}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{620FC257-2892-4EED-A3FC-5A31EB18C892}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-90
			:AdminInfo (
				:chkpf_uid ("{1D06CA11-FC0C-49A1-B41B-0341E62447B4}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http
			)
			:src_adtr (
				: HttpPortal
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{614B8249-7D30-4470-B17B-824EADBF7626}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C6013E2F-10B6-4DF3-B57C-D636A6A579C9}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F0FBF14C-F48C-428E-9289-7BBB8A2DD183}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: HttpPortal_pub
			)
		)
		: (rule-91
			:AdminInfo (
				:chkpf_uid ("{019746D9-FF1B-4C48-9BC6-9EBD3489328F}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: ntp
			)
			:src_adtr (
				: HttpPortal
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{01CC9265-1D81-4063-BA2A-E2105CC0646A}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{DA5C63B7-C32F-4B3B-8DD9-E751F4BA7690}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{956A1027-7DF4-4FBA-8EE0-FDF2DD282A4D}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: HttpPortal_pub
			)
		)
		: (rule-92
			:AdminInfo (
				:chkpf_uid ("{CA4A86D7-C134-43C6-A44A-1BDF6D2E554D}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebMailServerPub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5F535E86-EC52-4F62-9189-CDF13AD2F48B}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{AADC506F-98DD-4EFC-86C9-D175E4CA63E4}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F24053CA-FC54-4A08-9AF8-C7D547F7B51A}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-93
			:AdminInfo (
				:chkpf_uid ("{3CA5222C-0102-4D08-92D4-F414F76B817E}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: orapub-ext01
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{15E8D752-487E-47CF-B122-0FEDA637933B}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{06118095-7EBA-49CB-A040-EFC7B2D928EB}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{CDCEFE19-0974-4FD1-A12C-9CE788A31D79}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-94
			:AdminInfo (
				:chkpf_uid ("{C4F3A65D-0330-4AF0-924D-11B91CB611CC}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebMailServerPub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: https
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5B8DD369-296F-4A84-A361-66D28F565B3B}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{BD7EED6E-DF53-43CA-AF65-F83CD8A4D34B}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E02FEAFB-1C1E-492C-8AC0-2D674E825DEC}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-95
			:AdminInfo (
				:chkpf_uid ("{DCB48A4B-8595-45C1-AA31-893B9C769549}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: orapub-ext01
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: https
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2E424BFC-4E55-4059-9754-2FD7CE229C83}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2A31F55D-D6FC-4BDF-86F9-0CCD0F6C3F54}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{527E5447-3EAF-438B-AFD2-020A2F04CE2A}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-96
			:AdminInfo (
				:chkpf_uid ("{BE18F9A8-4D96-44E8-A84F-A6319E34C9C6}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebProxReve_OTI_NGinfo
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: https
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6FB0309E-E8C5-4EF3-8D84-D7EA87F769F2}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse_alias2
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8E50A194-078E-4B46-ADAC-E51E349F9587}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D37E270B-7FEC-4961-A36A-9E467078C00B}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-97
			:AdminInfo (
				:chkpf_uid ("{89D0F008-F159-4134-A552-FD63B95B4816}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: smsmt_pub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: https
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{94ABCB7F-647F-4BA9-A1CE-B82525C0BB44}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse_alias3
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{325C5F48-B80B-4776-BCC3-7591590E17B7}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{799C6FD4-A471-4553-9663-72619E5E4E00}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-98
			:AdminInfo (
				:chkpf_uid ("{AAA00164-F7BC-41E7-BC54-7E515429F56C}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebMailServerPub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http_444
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E728BCBE-ACA0-4348-B008-08F2CCFAD12C}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{063391C0-7D04-490B-ABCD-083E2CF5E4E1}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{98452E15-C366-4024-9F60-88043294840A}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-99
			:AdminInfo (
				:chkpf_uid ("{F6A29E74-90DD-4B98-87C0-807B7099B5B8}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: orapub-ext01
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http_444
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{939DF77E-4522-4B14-8706-9C91648DFD73}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FFDE0ECC-88C5-491A-B7CF-2DAD12999472}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8CC3F338-0D9D-4083-B81F-55F7EDBDFF87}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-100
			:AdminInfo (
				:chkpf_uid ("{79F1C708-3591-4BDF-9984-4192193E0CE7}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebMailServerPub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http_446
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{DB2349A9-272E-4AFD-8963-18DFD4C89BCA}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D274B61F-F75D-4F14-B4BE-3490A5EE69C2}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{86D5FB39-AFFC-44AA-81D5-DEC21ED61608}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-101
			:AdminInfo (
				:chkpf_uid ("{AFE073DF-081A-4467-AF3C-EAC402800966}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebWzwOnlinePub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: https
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{437C32FE-5FF4-40DC-9652-F065F22785B0}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse_alias6
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{85D27528-1142-4B17-80F3-029489EA3B03}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C0FEFF18-38CB-46A0-882E-4997D6D50B56}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-102
			:AdminInfo (
				:chkpf_uid ("{9E306F8F-2224-4644-AE79-30732D8A5F6A}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebNewMMBOX
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: https
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FE9D3C21-A7E2-4D5C-ABB9-E90CE5187DD1}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse_aliase7
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{13C34323-2B76-44A1-B720-2206ED619034}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{36605827-45E8-44AB-B605-ED8EE5B0F67F}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-103
			:AdminInfo (
				:chkpf_uid ("{313D9829-3E78-4C24-84CA-F98943BB460B}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: orapub-ext01
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http_446
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9349687F-8C2E-47A1-A67B-DE58F68FA4D6}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{A742A1B9-ACFE-43FA-8318-6DAB0F003561}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{BBABDCB9-3F34-4325-84EF-4F6936F570CF}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-104
			:AdminInfo (
				:chkpf_uid ("{5A52D302-8D37-4CA1-ADD4-2D3EE8F3FDE1}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebMailServerPub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http_447
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{07F35C26-5F7C-4BD3-ABD2-E5E9F0AC1938}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9C0F2979-205D-46F7-8F8B-D9F7EA687C51}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6EBE0FFC-4D74-4565-AE95-73F952D4E4BD}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-105
			:AdminInfo (
				:chkpf_uid ("{C9BE64D8-77EF-4517-AE38-B240821A57CC}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebMailServerPub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http_448
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{83264205-D4CC-4E3A-A5EE-6CA69A90E3C4}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E393D147-B140-432E-9E6A-44938E736FAB}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{63A916DA-A4ED-4327-8BAC-32CDA2CBBECE}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-106
			:AdminInfo (
				:chkpf_uid ("{6169B167-C95C-4B9D-9FC8-65B94FC66FF1}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: orapub-ext01
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http_448
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C18CDA39-65E6-43D3-9776-BA710688CE62}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{EED44915-BCAA-4F0D-A2F4-246AB1D04B6D}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{29964C79-B805-4799-B108-37DE0D914D2C}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-107
			:AdminInfo (
				:chkpf_uid ("{8EA3E830-8277-4039-B446-DEFD354BDBC3}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebMailServerPub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http_449
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{78204919-6F9C-44F4-83EA-282AD7594D64}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F459A453-D5FC-4C81-9FE8-9EE1C9328E50}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{DB861FAB-44FD-47B4-8922-E3AD7751FEB2}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-108
			:AdminInfo (
				:chkpf_uid ("{EE44B65E-8F5C-4ECB-8CC8-802DCFE9B302}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: orapub-ext01
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http_449
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{360F098A-52B3-482D-AC9A-A2AFB485FBE6}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{807A9741-AF3C-489A-9DFF-40455ECC30BE}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{72D4A885-A9F3-493F-92F6-2EABBAE1CFC2}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-109
			:AdminInfo (
				:chkpf_uid ("{D9049CC9-50B9-4D92-8E5C-B94DE84BFAAB}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebMailServerPub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http_450
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{34A9DD91-0C37-4D57-90AE-1670CBED142E}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{1D82B408-91FC-4E7B-A110-4793C719BEF4}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{4D2FDD61-6F9F-4F19-8C96-DB28AE9E00EB}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-110
			:AdminInfo (
				:chkpf_uid ("{FDD1A6BC-BEF5-47BA-ABE5-32233E9FD4F1}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: orapub-ext01
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http_450
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{26693FCB-478A-40D2-B6DC-71BC0A7AEB83}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{60DC95DA-7FB1-4145-A9DE-8A4CC8119D0D}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3B9246E6-884F-4EDC-A9F2-235E5FD233A6}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-111
			:AdminInfo (
				:chkpf_uid ("{F30CA3E7-3361-4816-85EF-E0D3E15F3DB4}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebMailServerPub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{BAE9B3F6-7315-44D0-A925-6D78944E00DE}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FC86A501-5FF3-4C01-B8AD-2F3F9D150E0D}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{02716E78-6C90-4F16-90B9-EEB316E2AFF3}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-112
			:AdminInfo (
				:chkpf_uid ("{7912D0C1-F59C-4E3E-8AAB-65BA7D815ECA}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: orapub-ext01
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{243F4140-801B-40D9-A402-FA0EA89F1498}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{EEC6550C-7F68-4D32-911A-2AF5197B32C9}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{107766C4-0B66-4142-92E3-103503D847FC}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-113
			:AdminInfo (
				:chkpf_uid ("{BA1F0EAB-C8CA-4DAA-940A-BA0787BDD393}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebMailServerPub_fun-tones
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: http
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{AA36D61E-6018-4AFC-8648-C8CAEE7F3C51}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse_alias
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{4A2D426F-59EF-471C-BA58-2C78B2183B7B}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{AA31D68B-CC8B-4DBD-BDF7-CFB0B06369D8}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-114
			:AdminInfo (
				:chkpf_uid ("{C7B24C58-4AA4-42E6-9958-565C82A29448}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebMailServerPub_fun-tones
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: https
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E64F3BE7-D9C0-4BCE-9FA4-43BFE2CA52D8}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse_alias
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{EAF1302F-2642-47C5-937F-F1BBCA9DD5C0}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8AD8B18C-212E-4E2A-A4BF-53B201F41157}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-115
			:AdminInfo (
				:chkpf_uid ("{781B1F64-69DD-4A63-9583-5FA92EAEFC87}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: WebProxRev-test-pub1
			)
			:global_location (middle)
			:install (
				: (Any
					:color (Blue)
				)
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5BED2694-415D-431C-8D1E-ADC060A3D772}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverseTest_alias1
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{BD9F226C-86D6-4D3B-9948-3BD937D08AD6}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{1DDC1153-9C5E-40A4-8AD6-55C6753A413C}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-116
			:AdminInfo (
				:chkpf_uid ("{B384E1DA-B218-41CD-93EF-D4F121890E27}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_NOC_IPNGN
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: SI_SAdmin
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{29BB3971-338B-4106-B8BC-539CA9A1B025}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9C1911F2-508C-440B-80F1-8477E03D6500}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9C225366-7B3C-458D-BC57-7D0C72A4C543}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-117
			:AdminInfo (
				:chkpf_uid ("{F576D54B-861D-403A-95DD-8E2F3486548E}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_41.190.238
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: SI_SAdmin
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{145B3E0E-3399-48CB-86A5-33B685ADA307}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{4FB45FCB-D474-4DB7-841A-221FFF2A7344}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E12DF588-68BD-4D19-B553-FF2647B1B2A9}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-118
			:AdminInfo (
				:chkpf_uid ("{13B6718D-71F7-43A7-9685-5287E43F45AA}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_ISP-NOC
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: SI_SAdmin
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{19E38143-39A4-4E45-973C-70613ABCF4A2}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{93355BC4-A7A3-4DB4-87E9-3CEC3F1FA2DB}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E7702070-789D-4372-A75A-AC3F125FCBB7}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-119
			:AdminInfo (
				:chkpf_uid ("{C9CC7737-7329-4324-9CB3-082ED099BEBE}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_ISP-NOC
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: SI_Admin_1
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F3E8256C-89AA-4988-A3A8-AB4FB58C7366}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{A9919A61-AA2C-497E-B706-AA1FB458D46D}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6DC8760A-99A1-40E9-9B32-2955863784CD}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-120
			:AdminInfo (
				:chkpf_uid ("{3CFFC0A7-EA07-45D6-8006-F0B88F178396}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_ISP-NOC
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Pc_Super_Entreprise_1
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B155D02C-A817-4358-BBF6-2D1ECB3079F1}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9CEE4108-AA2D-4657-AE57-207C3E57E48D}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0A2EFAD7-13E9-4BF1-BEC7-409A96AE6687}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-121
			:AdminInfo (
				:chkpf_uid ("{DDE817B8-EE66-425E-9C89-43473F543ABD}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_New_ISP_NOC
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Pc_Super_Entreprise_1
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0BAFD9CE-82D1-41B4-A499-30DB39CD26A6}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0BB5BF85-B7BF-4273-ACBA-A4362B28129E}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{19835B9D-B082-4A98-BBE7-592B2F5BC5C5}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-122
			:AdminInfo (
				:chkpf_uid ("{A7EA1347-9ED1-4669-8033-BB89BAF41777}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_ISP-NOC
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Pc_Super_Entreprise_2
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{19436D43-7965-45E4-87E2-A60716894188}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{ED07D3A1-250E-4164-8472-499F8998FD3D}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{02C689AA-18D4-4D87-9B27-A17752864F70}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-123
			:AdminInfo (
				:chkpf_uid ("{6487E256-97D8-4B64-B223-6C7D79DADC7F}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_New_ISP_NOC
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Pc_Super_Entreprise_2
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{A34F02D1-8C92-4B47-AF8F-34C178E2D813}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{112CB8EC-2725-4A2D-9303-A8504D7918F4}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C982693F-E6E8-4D57-8017-4C5C6318EC6C}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-124
			:AdminInfo (
				:chkpf_uid ("{7585ACDC-FE29-46C9-A011-93CBBACD901F}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_ISP-NOC
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Pc_Super_Entreprise_3
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D23729E9-662B-4D73-9B58-93229B3C3C34}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FB88497F-9A17-40CC-AE08-C3E72F9E2ABF}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{267A6BA8-CB8B-4AEA-95E9-C4CDF48E8DBA}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-125
			:AdminInfo (
				:chkpf_uid ("{7B05E56C-AEEB-45B7-967D-2B8EDF55EEC2}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_New_ISP_NOC
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Pc_Super_Entreprise_3
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{69BF87E5-E438-41F7-AD27-BAC1C9753E6A}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{44376792-6737-4D4F-946A-28EAF8B0E30D}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{17B6C631-BEAC-4B40-85C7-928BE39DFB43}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-126
			:AdminInfo (
				:chkpf_uid ("{382D6B97-09EB-4003-A503-6990F7C2E90A}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_ISP-NOC
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: G_Superv_MSC2
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D718BAD1-00F8-4108-B072-1F602A28805E}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FD49FFAF-5AFF-45DB-887F-7A5FC2AED025}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{673E774E-2961-4023-8422-590CF67A8A89}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-127
			:AdminInfo (
				:chkpf_uid ("{74997228-E9A2-4947-A186-24B3C6096856}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_New_ISP_NOC
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: G_Superv_MSC2
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5238F020-974A-4FB6-A4B4-D8C78DD9D229}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{073FF6ED-D874-4431-910A-D8B156B64628}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E81D1CA3-5D21-4723-8FAF-789E32EEC23A}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-128
			:AdminInfo (
				:chkpf_uid ("{5E89EB8E-A248-4674-BD65-37C71C5F7014}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_ISP-NOC
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3798C86F-F235-40E1-8A65-59DCE72E3E78}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{76F8CE76-6C90-498A-B9D3-38D043D528BD}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{989DE16A-4B74-4C90-BFCC-06DB838FA18F}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-129
			:AdminInfo (
				:chkpf_uid ("{3FF39ECE-7CAA-4D72-9610-98C77DE95690}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_New_ISP_NOC
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6FE9AEC0-E08F-4E2D-9816-997EE3419A28}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{EBB5537E-F416-4B85-A47A-529F1C0F5AAC}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{EE8C8B43-4C3D-4CD6-9B72-EFAD38B9E114}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-130
			:AdminInfo (
				:chkpf_uid ("{FC511510-8764-4A30-B22E-54B1B2027273}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: innovation.orange.com
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D5D33C55-41F2-4707-A69A-370ABF574C53}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E0081442-926E-478D-AF1B-1D5082DBAC7D}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8A644889-C539-45B3-B527-217AC743C8F9}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-131
			:AdminInfo (
				:chkpf_uid ("{0F466C14-D0F8-46BE-BE50-674E13A906E8}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: URL_OrangeMoney
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0C6600ED-9C94-4882-B8B1-64127723B142}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F39A2029-DCE7-4F86-98DD-2937FB158110}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3AEB1E43-3394-4DA3-B0E6-AE52250C1B74}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-132
			:AdminInfo (
				:chkpf_uid ("{A9B70995-2E92-4ED9-AC5C-57BA612C6A99}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: URL_IWEB_Money
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{625C0F6D-4444-4095-AF35-0051D20B5226}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{DF2F01AB-9458-488A-A659-1540FF1D409D}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{20E87813-B846-49EB-9C8B-B3D663EBC819}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-133
			:AdminInfo (
				:chkpf_uid ("{5394BB82-B77A-471F-BC42-E9FD78588809}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: URL-omcmg-preprod
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{BDAA8D54-ECEB-413B-AA89-8FB34B03EADC}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{28E65F80-A28A-4135-9930-D14038315555}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F117256C-4887-4957-A5F6-F5D2C4FC653E}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-134
			:AdminInfo (
				:chkpf_uid ("{DC38D3D5-B54F-4D05-B303-14D3B903784E}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_E-vidy_orange
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2FA82479-411E-4197-98B6-55AC2BB09BFF}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{EDF5146A-9070-497D-B6F4-8F70E67CB7CB}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{50BEDF9B-27CF-4E58-83F6-D9B047478F01}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-135
			:AdminInfo (
				:chkpf_uid ("{055F16EB-CD8C-4A74-BB59-96E60FDB1E1F}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Url_webftp_oma
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3D1C6B06-D9E4-4D78-8271-E42E5CD97455}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E92BA4F1-2EDE-442A-B405-87CA9B005D63}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{05A02E5C-6BE7-42F0-B4BC-43BD2400CBE4}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-136
			:AdminInfo (
				:chkpf_uid ("{9CAD81C7-65DE-4B7E-88FD-7F73531C8872}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Url_reports.orange-money.com
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{13817EFA-A99E-493C-91FE-70613E2419C3}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{425A52D2-D83A-4905-9D75-DF1DCEB40BC8}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{28801CC9-B967-4A53-8AA8-9325FEA3F224}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-137
			:AdminInfo (
				:chkpf_uid ("{5644C35C-7C26-4340-B8D5-392A5230453B}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Url_rccare-addon.orange-money.com
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3348A4A8-E6AE-4E8B-934B-AD0247A49A2F}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0A238789-6085-4330-B805-BDDC4EB51628}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D198F003-D5E3-4E21-A0C8-E373054927D2}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-138
			:AdminInfo (
				:chkpf_uid ("{F4C9CD25-C8E6-4193-A751-D6E227640778}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: URL_cdn.webtv.multimediabs.com
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{50810DC0-4040-416F-BCE3-B2BEA43B5F6E}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8174A467-9F08-495A-979F-D7F97E4F585A}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D61E87F2-0AE0-4F8D-9FAE-ED5D770363FF}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-139
			:AdminInfo (
				:chkpf_uid ("{DE4B752C-8BBD-4C12-A1C5-7DE1C62EC8AC}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: ccare-addon-pp.orange-money.com
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0AEED2D2-C2D5-4DA3-92F2-C7615C7B97E5}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B5901C81-EB2D-43B7-9D06-E65CB58F4F84}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{499AA5E9-5B66-46A2-A5B6-4D398F71D3DD}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-140
			:AdminInfo (
				:chkpf_uid ("{6F12638F-6F3C-4BAC-B442-7C49F7E33BD9}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: secure-madagascar.orange-money.com
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{1C8A188F-DE69-4273-9F0A-75EEA83CF12D}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{21A0C071-6702-4B5F-A345-1E48044B0110}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{A3B2FF65-1366-4ECC-8856-5F24FA37C1E5}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-141
			:AdminInfo (
				:chkpf_uid ("{20D75B16-88AE-42A8-8465-1EF3326794C6}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: IP_41.204.120.201_Gasynet
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{772B3B13-6192-4EB6-980E-C72EEF51A57E}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{7A9E2822-6FC1-42E8-9039-6CDCF2E76C8A}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{A16755BF-5C8B-45E6-91ED-D61D9488F67C}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-142
			:AdminInfo (
				:chkpf_uid ("{1978D68F-370F-46BE-9493-AA937EB07EB5}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: ftp.volubill.com
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{4ECFC7EB-B6DC-4099-984F-598D1A9AD88F}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F3628226-3307-47BE-9D8C-A8901CF1E0C0}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FE726EAC-DE6B-4433-A456-F3DE4FDB4338}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-143
			:AdminInfo (
				:chkpf_uid ("{6986CEA8-9F5F-485F-9F6A-4E18D1335749}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Net_Noc_BMOI
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{ED17844B-85B4-421B-8569-1348356CA202}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{ABEA841C-33AA-4F29-B893-3881A7F660EC}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3AE8A67D-E5E8-47D7-BCFB-8841E5EE8370}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-144
			:AdminInfo (
				:chkpf_uid ("{D0039822-B68B-4AA0-AE05-2374EBA8F690}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_noc_bmoi
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B2309E01-7815-4A23-8C27-2B51D0962715}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D0B8E675-810F-4303-9ACC-292F5EA9E40A}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D8DD47C7-A53A-4BF0-8A10-768D52E069AA}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-145
			:AdminInfo (
				:chkpf_uid ("{546A14C6-592C-4906-A0D0-4BCCC137DEBE}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_noc_bmoi_v2
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C6ACD652-5732-4C45-B1B0-95C55076255A}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B48EA537-6B88-4311-82B9-4C0D4081439F}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{10BF9F3A-2196-4BC8-83D8-748FF2F92FE9}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-146
			:AdminInfo (
				:chkpf_uid ("{40B98CC3-C892-4CD0-B036-EC734D8D1956}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_noc_bmoi
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: G_Superv_MSC2
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E9C55138-B81C-42CD-875F-A01BC5A4AF7F}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E2D28542-A6D1-4D50-8067-967B1E8FAE6F}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6C71618C-F513-458B-B190-171C9FF0A870}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-147
			:AdminInfo (
				:chkpf_uid ("{65511E89-FA43-4674-9BCA-99242866C2C2}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_noc_bmoi_v2
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: G_Superv_MSC2
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2403E76B-4C2D-4417-A8AF-4B6E30BF95F0}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{58719C6B-5194-400A-88B5-4543E518814F}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F16588B7-96CA-4737-AE3B-21C90D8D3594}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-148
			:AdminInfo (
				:chkpf_uid ("{20E4B9AC-E447-438C-B3C5-CBAF77EC6685}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_OBS
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: SI_SAdmin
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E857C78D-4279-464D-9A04-A189E9CA5075}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{EA06DD4A-03DA-436B-800A-9E322B2F369F}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{96EAFDFB-309B-43F1-8698-0BBA93B958E8}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-149
			:AdminInfo (
				:chkpf_uid ("{BC2B7CE1-1C8E-4408-81D7-FF74C9972E6C}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: IP_41.63.159.250
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: SI_SAdmin
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FB0B8E9A-BDB0-4B1D-AA94-113EEF5B8E25}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F5DC95D9-BCCC-46B2-9A9C-793A1F1852D6}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{7415E77B-05FC-4605-8872-9E0FAC2C7F29}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-150
			:AdminInfo (
				:chkpf_uid ("{F7360FC6-7745-41BA-A7FA-EA085AEFA25E}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Srv_test_vpn
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: SI_SAdmin
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{BD297281-B197-4681-B90E-230079092826}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E541C085-EF42-4C5D-B764-71DF741F4314}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{EB7ABDF4-18FC-4FAA-9DE2-8C200D1F88BF}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-151
			:AdminInfo (
				:chkpf_uid ("{A8248333-52A4-434B-8D01-C315ACB8BD17}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_OBS
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: SI_Admin_1
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{35778788-6E41-4A4F-BF6C-2BA37477A32C}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5B9132F2-DA55-40EF-9556-3634793E9A60}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{99073498-1A2C-4393-884B-19ED13FB519A}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-152
			:AdminInfo (
				:chkpf_uid ("{2C235CD9-A79A-40B7-807A-78849CFD26FE}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_OBS
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Netback
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2DCF934D-0691-49B5-83DA-BCA1EBA38E2D}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{21478E50-D5F0-43B9-B7D5-604E179069C5}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E1253D58-AA02-4284-93DA-47EDD464F49B}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-153
			:AdminInfo (
				:chkpf_uid ("{B2CA1DA3-9EA6-4E96-AAC6-C971A8A6D2C9}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: DNS1_OMA
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: SI_SAdmin
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6DBA5CB6-B45D-4BAD-A3C9-06A5A52CCC7F}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{A64590CE-A463-45E7-86D9-1B57EE81BCBB}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{DC601B5D-0846-49C1-940C-A916DE4979A4}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-154
			:AdminInfo (
				:chkpf_uid ("{7989C5D2-675A-45C1-A25A-6D02E4998475}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_dnscache2
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: SI_SAdmin
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{19AC6C36-ADA9-408D-891D-13C29D3A5E5E}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B48DB5A9-CF4D-4F6B-88F1-D5B9559C64D9}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{AEC874AA-FD8F-45A0-A68C-7AC426661BE2}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-155
			:AdminInfo (
				:chkpf_uid ("{79EC709C-97D6-4B58-A964-2271F0468404}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: DNS1_OMA
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Netback
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{AB418338-8BD0-418F-BAE3-B9CCDC2D5F24}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C25F1F5D-A8C4-42CA-A68B-B730931FB3A5}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2D6635AE-5A3F-41F6-86B6-9C28B6CC4503}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-156
			:AdminInfo (
				:chkpf_uid ("{416B254D-F247-4E9C-BCF4-7FE13F97BBBD}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: DNS1_OMA
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: srv_netbackup2
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{292DBF7B-AF46-4287-9588-F0CF28503910}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D4001261-408B-48AA-B5D7-51D4A7132A98}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{26A716FC-A87D-4491-80F5-CCB8680DB992}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-157
			:AdminInfo (
				:chkpf_uid ("{201FF68F-7B84-4AFC-834A-B30E727A1CE5}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_dnscache2
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Netback
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2747817A-7543-45E7-B2A8-2CEFB446CD95}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2B5AE7B9-A5E8-45A5-8B70-664227268A3D}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{1225D69B-D367-4F91-B5F4-240FCE5C2AA6}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-158
			:AdminInfo (
				:chkpf_uid ("{0613EF1F-CCCD-42DC-A966-D5430C213963}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: DNS2_OMA
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Netback
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D3F9C2C0-A039-428D-B3F1-D16B2F844AB2}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{822D1AC0-86CA-4495-A1BC-D842E272433A}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2A083D9B-FA90-44D9-BF0A-7AFD79A2F72F}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-159
			:AdminInfo (
				:chkpf_uid ("{80985AB9-806E-4AF4-BC8F-AE9E9643EDA5}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: DNS2_OMA
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: srv_netbackup2
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{02F70C1C-0BF7-4576-8F4C-C2C7FBDA4928}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9217F916-30B7-455C-8936-D73A0F0B65B4}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0EB0B115-C799-4DFA-B6CC-AFEAB9DD7D3E}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-160
			:AdminInfo (
				:chkpf_uid ("{CF517358-63C5-4083-A745-045176A8351D}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: fw_asa_5540
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: SI_SAdmin
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{90447479-10B1-41BE-808E-C97B749D79C7}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{CCF52715-B5C3-4248-A573-2A217E8AD651}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E1E0009C-1CC7-4954-8E40-72500745BB23}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-161
			:AdminInfo (
				:chkpf_uid ("{6A38BD5D-9F22-49FE-A5E2-BE27BC57A60D}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_test_bed_Zebra_pub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{00743017-648E-4F5B-B928-CF3766007C7A}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse_alias5
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{955F195A-8F4D-49E2-BECB-C10550771755}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{AB01472C-DEE6-4CC8-AC95-322CDB030E67}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-162
			:AdminInfo (
				:chkpf_uid ("{745DF054-B398-492A-B082-AB3081DF47AE}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: ProxyReverse2_pub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{45A46EE7-176F-4C1E-9B66-63E922A889AF}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: proxyreverse2_priv
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{21C0D9BA-01FF-41C8-8D2D-2FC7AC4047D3}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{919A5CE3-2F5F-4AC7-AF3B-D485E5045947}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-163
			:AdminInfo (
				:chkpf_uid ("{BEBE77C3-8A6D-4DF3-9A6C-BF5017357D69}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Srv_Prtg_Pub_Test
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: (Any
					:color (Blue)
				)
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{17A38552-68B9-4F38-BA75-D88D6F5B1991}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: ProxyReverse_alias4
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0EB1156D-A8ED-4D81-8437-DE11AF9E6780}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{001A083D-94BF-4BB3-8EB4-E1C2810F7E31}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-164
			:AdminInfo (
				:chkpf_uid ("{6AA4090B-6D1A-4886-AC79-76A666BE8187}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Srv_Prtg_ISP
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: ProxyReverse
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{1D0639A5-971A-4C64-A263-74ADA35AB7BE}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5ACAFCB9-1F78-48AC-B247-D2BAE9509A90}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{15DAEAFA-AA3E-440F-9A06-CDF060250A07}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: Srv_Prtg_Pub_Test
			)
		)
		: (rule-165
			:AdminInfo (
				:chkpf_uid ("{D0D657C4-B764-4C80-85DA-07B95C085193}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_ftp-broadcastonair._fr
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DCCS_DVR
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6F17F42E-FCFD-4148-9A38-44889203E5B6}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{30D4705F-F885-4958-9525-9CC82C0B47B7}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{CE23C3FF-B551-4489-8EBC-E51A15FFBE0D}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-166
			:AdminInfo (
				:chkpf_uid ("{AC8DB06D-C520-41DD-A092-45305809AEC0}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_ftp-broadcastonair._fr
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DCM_RHM
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0D99F294-ACAA-4500-A248-8DFB3B0FB3C5}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{0A7E8D76-F802-421F-ABFF-344FC7640478}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9A8D7DC7-34B7-42FA-9917-7F870560DAF7}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-167
			:AdminInfo (
				:chkpf_uid ("{76EE9976-1398-4871-9E07-44D6DDC2BE65}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_ftp-broadcastonair._fr
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Borne_Internet_DMCC
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FCB1767B-0A82-4C89-85C6-8BF5F301570A}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{48E1078A-4883-45BE-AF63-67132FA0FA05}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D1253737-8536-4F08-88CF-B49E2B8C51D5}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-168
			:AdminInfo (
				:chkpf_uid ("{E3AE2445-CEF9-4064-88DF-13A1C3806150}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_s155945973_onlinehome_fr
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DCCS_DVR
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8BEF379F-DD60-4271-8CB6-23D36D07C3F2}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{7AC51D6B-6E3E-4D5A-9C87-13DB28211BA7}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C27E1F9F-0B10-499B-AD36-89832C55D411}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-169
			:AdminInfo (
				:chkpf_uid ("{13106C2D-224B-4EF7-828F-9643CB55E8AE}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_ftp_jirama_Orange_Money
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DRH_ERN
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{77B60528-1CAC-4F93-8B99-2D5C61F2163E}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{7FBC2F6B-3250-40E1-A895-41569697C1B8}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{4836F6BF-1027-4398-BB6D-2E1C8043446A}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-170
			:AdminInfo (
				:chkpf_uid ("{713F10DB-3DF7-448B-8E12-FB880A3F34D9}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Site_mfsafrica_biz
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DCVI_OHA
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E0B6EFE9-EBD3-4944-B82B-3AE357F7C1A3}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F5D11BB4-C477-4764-B1C3-182D59ACD130}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{4F652886-57D6-48F8-A421-67146BD6F734}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-171
			:AdminInfo (
				:chkpf_uid ("{AF4254A5-9AC7-4A7E-BB06-05129669DAD0}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Site_mfsafrica_biz
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DCVI_ONT
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3D6CA070-577E-4F94-822F-5A3D81155F24}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{07253657-34EF-401C-B954-E19C571E88DD}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2F08EF4B-F9B5-401F-A488-8BA88C630A7D}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-172
			:AdminInfo (
				:chkpf_uid ("{6CC63A05-4F0C-4F82-85BF-F0102EC559D5}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_ftp_jirama_Orange_Money
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DCVI_OHA
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E8C87488-8DC6-47E0-BC19-2CCBB7FC0EF1}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3D0DFF9F-8760-4CEF-8164-48732368B713}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C1DFD878-3988-45AC-8FB5-C69D3CC519D8}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-173
			:AdminInfo (
				:chkpf_uid ("{48BCE973-B4E7-44F4-BEB6-A0AE6EA62486}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_ftp_jirama_Orange_Money
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DCVI_ONT
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3A08A46D-8D5C-4FD3-AE87-68FB387E8B2E}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9641E158-DDF3-47C4-9B95-9CF93BDA21BF}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5332EA7D-A93F-4BB7-B13F-1AAA84D4710A}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-174
			:AdminInfo (
				:chkpf_uid ("{C1C3EC63-20EA-4C05-B632-5DFC1DC35CB7}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Site_mfsafrica_biz
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DSI_SVA_FMR
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{14CACAE7-5616-4C71-A427-D7E230E593CC}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{201781CE-373C-41A9-966C-91FCFB3210B7}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{37A95882-DF20-44B5-8BD8-8695E23D7912}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-175
			:AdminInfo (
				:chkpf_uid ("{AAC583B5-B9B3-4C8A-87B0-0DBC295907A3}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Site_mfsafrica_biz
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DSI_SVA_SANDRATANA
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{67141A27-FE05-4CF4-83F3-BE1CC3172E0A}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{1F1E24BD-78EA-42A7-B28E-EED911AEB611}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{DA2A6F5F-787D-41EC-A158-3FCEF987F557}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-176
			:AdminInfo (
				:chkpf_uid ("{09CE3D85-2DE8-44A4-A026-55E6BD2B780C}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_ftp_jirama_Orange_Money
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DCVI_RGN
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9F759236-A9B0-479D-934E-E1E65BAD510E}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{687674A1-1AED-4AA1-99F1-0D7C45CCEB15}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C744C553-A492-4CB7-AF21-5275CC53409B}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-177
			:AdminInfo (
				:chkpf_uid ("{CAEA659E-2093-4517-8768-18219B0ABC9B}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: srv_ftp_jirama_Orange_Money
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DCVI_AML
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3CD69396-8B73-4E50-9382-E9A2E99F1E83}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{982CEDF2-C5DB-48BF-894C-A2AAABB52D54}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{221A8D39-B5F8-4F83-AFF1-1F2B8F37266F}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-178
			:AdminInfo (
				:chkpf_uid ("{DF851666-1B9F-4220-9299-16F3005B8171}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: test_smokeping
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{02C6D376-0A6B-46CD-B46B-F618F5522809}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{C560C31F-281E-4E97-BF5D-FC23A86B05E3}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5E0CE8DC-AE61-4C14-80B4-AB7A0917C2AF}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-179
			:AdminInfo (
				:chkpf_uid ("{12B91093-8561-4172-98A2-A72D72BA3B00}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: (Any
					:color (Blue)
				)
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Srv_Sniffer_Wireshark
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8D18E765-4CD1-4AF5-A4AB-5BA290833F9C}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D203D8BD-BD32-47F3-889F-C887250E99FD}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D8992EE9-2AD4-43DF-B251-B9807211555C}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: Srv_Sniffer_Wireshark-Pub
			)
		)
		: (rule-180
			:AdminInfo (
				:chkpf_uid ("{DC452E86-10C1-4DC8-A373-56E1621B8D64}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Remote_pop_orange
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DMCC_LVL
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F0B6E0A5-73F2-404C-91CE-B05490DF2F41}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{224DF916-AE4D-4B90-B727-5701850C58FD}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{77F4F4E8-20D5-4113-92A2-58B05300DAA7}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-181
			:AdminInfo (
				:chkpf_uid ("{5B02BA88-BBFB-4E80-BEAA-10C567E0E3CB}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Remote_smtp_orange
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DMCC_LVL
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F988A75C-7BF2-432F-A93E-21BE32F8994C}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{66F00F50-B8A4-4A3C-8210-FF284C5BDAAA}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{841EF357-204F-412B-872D-E1C2D1A9A3FC}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-182
			:AdminInfo (
				:chkpf_uid ("{C6EC06C6-F4B0-495C-A12E-D9BADDC09538}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: SMS-sender_Interne_Pub
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: srv_OBS
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F2DB0FC6-3506-4DE5-B6B0-BC42462DAB26}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: SMS-sender_Interne
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B63FC147-FC3B-49B0-AC3C-5F5B50088461}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F543916C-9FE3-4634-8B7E-292F065D0F47}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
		)
		: (rule-183
			:AdminInfo (
				:chkpf_uid ("{1568FEA9-0F41-4231-B108-BE01C40DB33F}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Peer_Mach_ftp
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Srv_Si_Onibe
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{822C9CD4-ED0B-4295-9722-A320631C736D}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3AEF2DA2-FBAF-40C7-A022-DAD801AFEC56}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{6C8EC982-9E9B-4DEB-B5B2-C21A281FF161}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: onilahy_pub
			)
		)
		: (rule-184
			:AdminInfo (
				:chkpf_uid ("{26C136A1-78C4-4FB8-A653-3A24FDA21DC1}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Srv_FTP_DHL
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: G_FTP_DHL
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{945599A1-B789-48A5-9264-F39338B2CFAD}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{B94A13EC-A6F0-4747-B0AE-ADF0ECEA38DE}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3EB500BB-6CE7-4DEA-8C83-C0CFEB28C243}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-185
			:AdminInfo (
				:chkpf_uid ("{37915A19-4F7C-40BD-93CF-DB37160B0EA6}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Url_savon-oma_blueline
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Srv_Betsiboka
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{AC2E1A0D-6708-4D9D-9055-E0A8B41C8C76}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{AA7689E7-AAEB-410E-8243-722F2107B11E}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{55E28793-A9C2-4968-9886-A68CCA0999C8}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-186
			:AdminInfo (
				:chkpf_uid ("{26D620A4-19E3-47A5-B9EE-258F027315BE}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Url_savon-oma_blueline
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DSI_SVA_RAB
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E74471A2-123D-4F15-9673-7B5F1FA87910}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{83955295-E002-49F8-90A6-4E21A296772D}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E2FD7FA5-C202-40A7-A284-D9EB5CCFEAA0}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-187
			:AdminInfo (
				:chkpf_uid ("{041328D7-7D4F-406C-B758-B618085B525C}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Url_savon-oma_blueline
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: DSI_SVA_SANDRATANA
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{3F58D204-19A6-4ECC-AE1D-B7BF7C16FA36}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F3CB081E-6960-4537-BBD0-A2E591B50B32}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{AA524774-83D5-4598-A2FD-C98E804E0CF4}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-188
			:AdminInfo (
				:chkpf_uid ("{982DFE7B-A92C-4301-826E-DA91512C61DE}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Url_savon-oma_blueline
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: PC_CRM_SOC
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{FB930F7D-4FFA-4290-A93B-71638B64BDF3}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{224FBF90-B83D-4F5B-A3E5-CF32841F2C92}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{5EC0F51B-77E9-4976-8BC9-AB477FD8D87A}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-189
			:AdminInfo (
				:chkpf_uid ("{C78DE2CB-0294-4E46-90E6-01FD964E5CBB}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Url_savon-oma_blueline
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Srv_Mpanjiva
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{DC4955FB-83D0-4C0A-9C8B-38803A897008}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{E5598BBB-9801-4604-9436-00B67F57C4EF}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{CC604A9D-A70C-4D69-86CB-7BA4BA0CBE6B}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-190
			:AdminInfo (
				:chkpf_uid ("{E9FEA535-CA07-4785-8590-6DC8A8CA73E9}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Url_savon-oma_blueline
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Srv_Mpanjiva_Test_Bed
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{8A37C0CA-E806-412D-BF66-8A49F450867D}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{F1AFE0C2-9434-42E0-8CBB-0732C09AF975}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{1600C1DD-8535-469D-8B70-E0281BBD5580}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-191
			:AdminInfo (
				:chkpf_uid ("{0745943D-92FE-42A9-B0D8-0561E3BDB9B2}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Eyes_Of_Network
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: PC_consultant_alcatel1
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{7B8C6EAD-9BAF-4B58-BF66-54B1A53A8C9B}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{9304BCE3-5D0C-415B-BB97-304227EF7672}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{156BD767-4EDA-47EA-A8A2-15FF9D676CCC}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-192
			:AdminInfo (
				:chkpf_uid ("{F8C58AEE-2B36-4DFA-99E9-9791E521019D}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Eyes_Of_Network
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: PC_consultant_alcatel2
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{205FDA01-33FD-4AC9-B83D-70B60F2A78D0}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{EAD9C303-4A1B-42AC-9428-1B558084196C}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{2F864772-8FA5-42FF-8978-414967910497}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
		: (rule-193
			:AdminInfo (
				:chkpf_uid ("{5DD2F53C-8AD2-4E27-9511-EC0693D0E435}")
				:ClassName (address_translation_rule)
			)
			:disabled (false)
			:dst_adtr (
				: Smokeping_test_telma
			)
			:global_location (middle)
			:install (
				: Fwent
			)
			:rule_block_number (1)
			:services_adtr (
				: (Any
					:color (Blue)
				)
			)
			:src_adtr (
				: Net_SI_OMG
			)
			:dst_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{DCB337B4-137A-48CA-A744-B9E1FCD57B2D}")
					:ClassName (translate_static)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:services_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{D71686B8-BF95-4618-B114-65C13F381C96}")
					:ClassName (service_translate)
				)
				:adtr_method (adtr_method_static)
				: (Any
					:color (Blue)
				)
			)
			:src_adtr_translated (
				:AdminInfo (
					:chkpf_uid ("{1EFB9F77-B824-4A4F-895D-F3ACCA780DDC}")
					:ClassName (translate_hide)
				)
				:adtr_method (adtr_method_hide)
				: orapub-int01
			)
		)
	)
	:party ()
	:if_info (
		: (192.168.248.7
			:objtype (gw)
			: (eth4c0
				:ipaddr (192.168.250.3)
				:has_addr_info (true)
				:addr_table (valid_addrs_list1)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s1p1c0
				:ipaddr (192.168.247.2)
				:has_addr_info (true)
				:addr_table (valid_addrs_list2)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s1p2c1
				:ipaddr (192.168.253.131)
				:has_addr_info (true)
				:addr_table (valid_addrs_list3)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s1p2c2
				:ipaddr (192.168.253.3)
				:has_addr_info (true)
				:addr_table (valid_addrs_list4)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth1c0
				:ipaddr (192.168.248.7)
				:has_addr_info (true)
				:addr_table (valid_addrs_list5)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth2c0
				:ipaddr (192.168.249.7)
				:has_addr_info (true)
				:addr_table (valid_addrs_list6)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (true)
			)
			: (eth3c0
				:ipaddr (192.168.250.131)
				:has_addr_info (true)
				:addr_table (valid_addrs_list7)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
		)
		: (192.168.248.6
			:objtype (gw)
			: (eth4c0
				:ipaddr (192.168.250.2)
				:has_addr_info (true)
				:addr_table (valid_addrs_list8)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s1p1c0
				:ipaddr (192.168.247.1)
				:has_addr_info (true)
				:addr_table (valid_addrs_list9)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s1p2c1
				:ipaddr (192.168.253.130)
				:has_addr_info (true)
				:addr_table (valid_addrs_list10)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s1p2c2
				:ipaddr (192.168.253.2)
				:has_addr_info (true)
				:addr_table (valid_addrs_list11)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth1c0
				:ipaddr (192.168.248.6)
				:has_addr_info (true)
				:addr_table (valid_addrs_list12)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth2c0
				:ipaddr (192.168.249.6)
				:has_addr_info (true)
				:addr_table (valid_addrs_list13)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (true)
			)
			: (eth3c0
				:ipaddr (192.168.250.130)
				:has_addr_info (true)
				:addr_table (valid_addrs_list14)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
		)
		: (192.168.249.138
			:objtype (gw)
			: (eth-s2p1c0
				:ipaddr (192.168.209.33)
				:has_addr_info (true)
				:addr_table (valid_addrs_list15)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s1p1c0
				:ipaddr (192.168.209.1)
				:has_addr_info (true)
				:addr_table (valid_addrs_list16)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s3p1c0
				:ipaddr (192.168.249.138)
				:has_addr_info (true)
				:addr_table (valid_addrs_list17)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (true)
			)
		)
		: (192.168.249.166
			:objtype (gw)
			: (eth4c0
				:ipaddr (192.168.249.169)
				:has_addr_info (true)
				:addr_table (valid_addrs_list18)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth1c0
				:ipaddr (192.168.210.1)
				:has_addr_info (true)
				:addr_table (valid_addrs_list19)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth2c0
				:ipaddr (192.168.210.33)
				:has_addr_info (true)
				:addr_table (valid_addrs_list20)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth3c0
				:ipaddr (192.168.249.166)
				:has_addr_info (true)
				:addr_table (valid_addrs_list21)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (true)
			)
		)
		: (192.168.249.146
			:objtype (gw)
			: (eth-s2p1c0
				:ipaddr (192.168.208.161)
				:has_addr_info (true)
				:addr_table (valid_addrs_list22)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s1p1c0
				:ipaddr (192.168.208.129)
				:has_addr_info (true)
				:addr_table (valid_addrs_list23)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s3p1c0
				:ipaddr (192.168.249.146)
				:has_addr_info (true)
				:addr_table (valid_addrs_list24)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (true)
			)
		)
		: (192.168.249.154
			:objtype (gw)
			: (eth-s2p1c0
				:ipaddr (192.168.208.225)
				:has_addr_info (true)
				:addr_table (valid_addrs_list25)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s1p1c0
				:ipaddr (192.168.208.193)
				:has_addr_info (true)
				:addr_table (valid_addrs_list26)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s3p1c0
				:ipaddr (192.168.249.154)
				:has_addr_info (true)
				:addr_table (valid_addrs_list27)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (true)
			)
		)
		: (192.168.249.142
			:objtype (gw)
			: (eth-s2p1c0
				:ipaddr (192.168.208.33)
				:has_addr_info (true)
				:addr_table (valid_addrs_list28)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s1p1c0
				:ipaddr (192.168.208.1)
				:has_addr_info (true)
				:addr_table (valid_addrs_list29)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s3p1c0
				:ipaddr (192.168.249.142)
				:has_addr_info (true)
				:addr_table (valid_addrs_list30)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (true)
			)
		)
		: (192.168.249.158
			:objtype (gw)
			: (eth-s2p1c0
				:ipaddr (192.168.209.225)
				:has_addr_info (true)
				:addr_table (valid_addrs_list31)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s1p1c0
				:ipaddr (192.168.209.193)
				:has_addr_info (true)
				:addr_table (valid_addrs_list32)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s3p1c0
				:ipaddr (192.168.249.158)
				:has_addr_info (true)
				:addr_table (valid_addrs_list33)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (true)
			)
		)
		: (192.168.249.162
			:objtype (gw)
			: (eth-s2p1c0
				:ipaddr (192.168.209.161)
				:has_addr_info (true)
				:addr_table (valid_addrs_list34)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s1p1c0
				:ipaddr (192.168.209.129)
				:has_addr_info (true)
				:addr_table (valid_addrs_list35)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s3p1c0
				:ipaddr (192.168.249.162)
				:has_addr_info (true)
				:addr_table (valid_addrs_list36)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (true)
			)
		)
		: (196.192.44.5
			:objtype (gw)
			: (eth-s2p1c0
				:ipaddr (192.168.209.161)
				:has_addr_info (true)
				:addr_table (valid_addrs_list37)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s1p1c0
				:ipaddr (192.168.209.129)
				:has_addr_info (true)
				:addr_table (valid_addrs_list38)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (false)
			)
			: (eth-s3p1c0
				:ipaddr (196.192.44.1)
				:has_addr_info (true)
				:addr_table (valid_addrs_list39)
				:overlap_nat (false)
				:overlap_nat_src_addr ()
				:overlap_nat_dst_addr ()
				:overlap_nat_netmask (255.255.255.0)
				:spooftrack (log)
				:external (true)
			)
		)
	)
	:conf_params (
		: (192.168.248.7
			: (vpnddcate
				:type (bool)
				:val (false)
			)
			: (ip_pool_securemote
				:type (bool)
				:val (false)
			)
			: (om_prevent_ippool_nat_for_users
				:type (bool)
				:val (false)
			)
			: (ip_pool_gw2gw
				:type (bool)
				:val (false)
			)
			: (save_data_conns
				:type (bool)
				:val (false)
			)
			: (save_control_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_unused_return_interval
				:type (int)
				:val (60)
			)
			: (fw_keep_old_conns
				:type (bool)
				:val (false)
			)
			: (perform_cluster_hide
				:type (bool)
				:val (true)
			)
			: (cluster_LS_mode
				:type (int)
				:val (0)
			)
			: (ip_pool_exhaust_ret_interval
				:type (int)
				:val (30)
			)
			: (use_sync
				:type (bool)
				:val (true)
			)
			: (use_limited_flushnack
				:type (bool)
				:val (false)
			)
			: (sync_tcp_handshake_mode
				:type (int)
				:val (1)
			)
			: (fw_hmem_size
				:type (int)
				:val (6)
			)
			: (fw_hmem_maxsize
				:type (int)
				:val (30)
			)
			: (connections_limit
				:type (int)
				:val (25000)
			)
			: (connections_hashsize
				:type (int)
				:val (32768)
			)
			: (non_tcp_quota_percentage
				:type (int)
				:val (50)
			)
			: (non_tcp_quota_enable
				:type (bool)
				:val (false)
			)
			: (asm_synatk
				:type (bool)
				:val (false)
			)
			: (asm_synatk_timeout
				:type (int)
				:val (5)
			)
			: (asm_synatk_threshold
				:type (int)
				:val (200)
			)
			: (asm_synatk_external_only
				:type (bool)
				:val (true)
			)
			: (asm_synatk_log
				:type (str)
				:val (log)
			)
			: (asm_synatk_log_level
				:type (int)
				:val (1)
			)
			: (translation_cache_limit
				:type (int)
				:val (10000)
			)
			: (cluster_mode
				:type (str)
				:val (HighAvailability)
			)
			: (translation_cache_expiry
				:type (int)
				:val (1800)
			)
			: (no_nat_cache_service
				:type (bool)
				:val (false)
			)
			: (availability_mode
				:type (int)
				:val (5)
			)
			: (fwha_sync_outbound_sa
				:type (int)
				:val (1)
			)
			: (need_sync_FlashAndAck
				:type (int)
				:val (0)
			)
			: (vpn_cluster_addr
				:type (int)
				:val (-1040478860)
			)
			: (fw_my_object_ip
				:type (int)
				:val (-1062668281)
			)
			: (vpn_udpencap_port
				:type (int)
				:val (2746)
			)
			: (EnableDecapsulation
				:type (int)
				:val (0)
			)
			: (support_L2TP
				:type (int)
				:val (0)
			)
			: (om_perform_antispoofing
				:type (int)
				:val (1)
			)
			: (tcpt_active
				:type (int)
				:val (0)
			)
			: (vpn_comp_level
				:type (int)
				:val (2)
			)
			: (ipsec_dont_fragment
				:type (int)
				:val (1)
			)
			: (IPSec_TOS_inner
				:type (int)
				:val (0)
			)
			: (IPSec_TOS_outer
				:type (int)
				:val (1)
			)
			: (is_ikehost
				:type (int)
				:val (1)
			)
			: (disable_replay_check
				:type (int)
				:val (0)
			)
			: (cphwd_round_robin
				:type (int)
				:val (0)
			)
			: (enable_OM_with_multiple_IF
				:type (int)
				:val (0)
			)
			: (keep_DF_flag
				:type (int)
				:val (0)
			)
			: (is_extranet_allowed
				:type (int)
				:val (0)
			)
			: (userc_rules_lm
				:type (int)
				:val (50000)
			)
			: (userc_rules_sz
				:type (int)
				:val (65536)
			)
			: (userc_key_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_sz
				:type (int)
				:val (16384)
			)
			: (inbound_SPI_lm
				:type (int)
				:val (40800)
			)
			: (inbound_SPI_sz
				:type (int)
				:val (65536)
			)
			: (outbound_SPI_lm
				:type (int)
				:val (40800)
			)
			: (outbound_SPI_sz
				:type (int)
				:val (65536)
			)
			: (MSPI_requests_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_req_connections_lm
				:type (int)
				:val (25000)
			)
			: (IKE_SA_table_lm
				:type (int)
				:val (40400)
			)
			: (IKE_SA_table_sz
				:type (int)
				:val (65536)
			)
			: (cookies_by_peer_lm
				:type (int)
				:val (20000)
			)
			: (cookies_by_peer_sz
				:type (int)
				:val (32768)
			)
			: (peer_by_cookies_lm
				:type (int)
				:val (20000)
			)
			: (peer_by_cookies_sz
				:type (int)
				:val (32768)
			)
			: (IPSEC_userc_dont_trap_table_lm
				:type (int)
				:val (10000)
			)
			: (userc_pending_lm
				:type (int)
				:val (25000)
			)
			: (MSPI_by_methods_lm
				:type (int)
				:val (20400)
			)
			: (MSPI_cluster_map_lm
				:type (int)
				:val (20400)
			)
			: (MSPI_cluster_feedback_lm
				:type (int)
				:val (20400)
			)
			: (L2TP_MSPI_cluster_feedback_lm
				:type (int)
				:val (20400)
			)
			: (MSPI_cluster_feedback_new_lm
				:type (int)
				:val (20400)
			)
			: (L2TP_MSPI_cluster_update_lm
				:type (int)
				:val (20400)
			)
			: (MSPI_cluster_update_lm
				:type (int)
				:val (20400)
			)
			: (MSPI_feedback_to_delete_lm
				:type (int)
				:val (20400)
			)
			: (udp_enc_cln_table_lm
				:type (int)
				:val (20000)
			)
			: (udp_enc_cln_table_sz
				:type (int)
				:val (32768)
			)
			: (om_assigned_ips_lm
				:type (int)
				:val (10000)
			)
			: (udp_response_nat_lm
				:type (int)
				:val (10200)
			)
			: (VIN_SA_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (marcipan_ippool_allocated_lm
				:type (int)
				:val (10000)
			)
			: (marcipan_ippool_users_lm
				:type (int)
				:val (10000)
			)
			: (user_auth_groups_lm
				:type (int)
				:val (20000)
			)
			: (user_auth_groups_sz
				:type (int)
				:val (32768)
			)
			: (persistent_tunnels_lm
				:type (int)
				:val (20400)
			)
			: (peers_count_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_sz
				:type (int)
				:val (16384)
			)
			: (ipalloc_tab_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_tunnels_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_sessions_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_lookup_lm
				:type (int)
				:val (10000)
			)
			: (max_concurrent_vpn_tunnels
				:type (int)
				:val (10000)
			)
			: (max_concurrent_gw_tunnels
				:type (int)
				:val (200)
			)
			: (fwsynatk_method
				:type (int)
				:val (0)
			)
			: (fwsynatk_timeout
				:type (int)
				:val (10)
			)
			: (fwsynatk_max
				:type (int)
				:val (5000)
			)
			: (fwsynatk_warning
				:type (int)
				:val (1)
			)
			: (fw_rst_expired_conn
				:type (bool)
				:val (false)
			)
			: (IPSec_cluster_nat
				:type (int)
				:val (1)
			)
			: (IPSec_main_if_nat
				:type (int)
				:val (0)
			)
			: (IPSec_orig_if_nat
				:type (int)
				:val (1)
			)
		)
		: (192.168.248.6
			: (vpnddcate
				:type (bool)
				:val (false)
			)
			: (ip_pool_securemote
				:type (bool)
				:val (false)
			)
			: (om_prevent_ippool_nat_for_users
				:type (bool)
				:val (false)
			)
			: (ip_pool_gw2gw
				:type (bool)
				:val (false)
			)
			: (save_data_conns
				:type (bool)
				:val (false)
			)
			: (save_control_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_unused_return_interval
				:type (int)
				:val (60)
			)
			: (fw_keep_old_conns
				:type (bool)
				:val (false)
			)
			: (perform_cluster_hide
				:type (bool)
				:val (true)
			)
			: (cluster_LS_mode
				:type (int)
				:val (0)
			)
			: (ip_pool_exhaust_ret_interval
				:type (int)
				:val (30)
			)
			: (use_sync
				:type (bool)
				:val (true)
			)
			: (use_limited_flushnack
				:type (bool)
				:val (false)
			)
			: (sync_tcp_handshake_mode
				:type (int)
				:val (1)
			)
			: (fw_hmem_size
				:type (int)
				:val (6)
			)
			: (fw_hmem_maxsize
				:type (int)
				:val (30)
			)
			: (connections_limit
				:type (int)
				:val (25000)
			)
			: (connections_hashsize
				:type (int)
				:val (32768)
			)
			: (non_tcp_quota_percentage
				:type (int)
				:val (50)
			)
			: (non_tcp_quota_enable
				:type (bool)
				:val (false)
			)
			: (asm_synatk
				:type (bool)
				:val (false)
			)
			: (asm_synatk_timeout
				:type (int)
				:val (5)
			)
			: (asm_synatk_threshold
				:type (int)
				:val (200)
			)
			: (asm_synatk_external_only
				:type (bool)
				:val (true)
			)
			: (asm_synatk_log
				:type (str)
				:val (log)
			)
			: (asm_synatk_log_level
				:type (int)
				:val (1)
			)
			: (translation_cache_limit
				:type (int)
				:val (10000)
			)
			: (cluster_mode
				:type (str)
				:val (HighAvailability)
			)
			: (translation_cache_expiry
				:type (int)
				:val (1800)
			)
			: (no_nat_cache_service
				:type (bool)
				:val (false)
			)
			: (availability_mode
				:type (int)
				:val (5)
			)
			: (fwha_sync_outbound_sa
				:type (int)
				:val (1)
			)
			: (need_sync_FlashAndAck
				:type (int)
				:val (0)
			)
			: (vpn_cluster_addr
				:type (int)
				:val (-1040478860)
			)
			: (fw_my_object_ip
				:type (int)
				:val (-1062668282)
			)
			: (vpn_udpencap_port
				:type (int)
				:val (2746)
			)
			: (EnableDecapsulation
				:type (int)
				:val (0)
			)
			: (support_L2TP
				:type (int)
				:val (0)
			)
			: (om_perform_antispoofing
				:type (int)
				:val (1)
			)
			: (tcpt_active
				:type (int)
				:val (0)
			)
			: (vpn_comp_level
				:type (int)
				:val (2)
			)
			: (ipsec_dont_fragment
				:type (int)
				:val (1)
			)
			: (IPSec_TOS_inner
				:type (int)
				:val (0)
			)
			: (IPSec_TOS_outer
				:type (int)
				:val (1)
			)
			: (is_ikehost
				:type (int)
				:val (1)
			)
			: (disable_replay_check
				:type (int)
				:val (0)
			)
			: (cphwd_round_robin
				:type (int)
				:val (0)
			)
			: (enable_OM_with_multiple_IF
				:type (int)
				:val (0)
			)
			: (keep_DF_flag
				:type (int)
				:val (0)
			)
			: (is_extranet_allowed
				:type (int)
				:val (0)
			)
			: (userc_rules_lm
				:type (int)
				:val (50000)
			)
			: (userc_rules_sz
				:type (int)
				:val (65536)
			)
			: (userc_key_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_sz
				:type (int)
				:val (16384)
			)
			: (inbound_SPI_lm
				:type (int)
				:val (40800)
			)
			: (inbound_SPI_sz
				:type (int)
				:val (65536)
			)
			: (outbound_SPI_lm
				:type (int)
				:val (40800)
			)
			: (outbound_SPI_sz
				:type (int)
				:val (65536)
			)
			: (MSPI_requests_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_req_connections_lm
				:type (int)
				:val (25000)
			)
			: (IKE_SA_table_lm
				:type (int)
				:val (40400)
			)
			: (IKE_SA_table_sz
				:type (int)
				:val (65536)
			)
			: (cookies_by_peer_lm
				:type (int)
				:val (20000)
			)
			: (cookies_by_peer_sz
				:type (int)
				:val (32768)
			)
			: (peer_by_cookies_lm
				:type (int)
				:val (20000)
			)
			: (peer_by_cookies_sz
				:type (int)
				:val (32768)
			)
			: (IPSEC_userc_dont_trap_table_lm
				:type (int)
				:val (10000)
			)
			: (userc_pending_lm
				:type (int)
				:val (25000)
			)
			: (MSPI_by_methods_lm
				:type (int)
				:val (20400)
			)
			: (MSPI_cluster_map_lm
				:type (int)
				:val (20400)
			)
			: (MSPI_cluster_feedback_lm
				:type (int)
				:val (20400)
			)
			: (L2TP_MSPI_cluster_feedback_lm
				:type (int)
				:val (20400)
			)
			: (MSPI_cluster_feedback_new_lm
				:type (int)
				:val (20400)
			)
			: (L2TP_MSPI_cluster_update_lm
				:type (int)
				:val (20400)
			)
			: (MSPI_cluster_update_lm
				:type (int)
				:val (20400)
			)
			: (MSPI_feedback_to_delete_lm
				:type (int)
				:val (20400)
			)
			: (udp_enc_cln_table_lm
				:type (int)
				:val (20000)
			)
			: (udp_enc_cln_table_sz
				:type (int)
				:val (32768)
			)
			: (om_assigned_ips_lm
				:type (int)
				:val (10000)
			)
			: (udp_response_nat_lm
				:type (int)
				:val (10200)
			)
			: (VIN_SA_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (marcipan_ippool_allocated_lm
				:type (int)
				:val (10000)
			)
			: (marcipan_ippool_users_lm
				:type (int)
				:val (10000)
			)
			: (user_auth_groups_lm
				:type (int)
				:val (20000)
			)
			: (user_auth_groups_sz
				:type (int)
				:val (32768)
			)
			: (persistent_tunnels_lm
				:type (int)
				:val (20400)
			)
			: (peers_count_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_sz
				:type (int)
				:val (16384)
			)
			: (ipalloc_tab_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_tunnels_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_sessions_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_lookup_lm
				:type (int)
				:val (10000)
			)
			: (max_concurrent_vpn_tunnels
				:type (int)
				:val (10000)
			)
			: (max_concurrent_gw_tunnels
				:type (int)
				:val (200)
			)
			: (fwsynatk_method
				:type (int)
				:val (0)
			)
			: (fwsynatk_timeout
				:type (int)
				:val (10)
			)
			: (fwsynatk_max
				:type (int)
				:val (5000)
			)
			: (fwsynatk_warning
				:type (int)
				:val (1)
			)
			: (fw_rst_expired_conn
				:type (bool)
				:val (false)
			)
			: (IPSec_cluster_nat
				:type (int)
				:val (1)
			)
			: (IPSec_main_if_nat
				:type (int)
				:val (0)
			)
			: (IPSec_orig_if_nat
				:type (int)
				:val (1)
			)
		)
		: (192.168.249.138
			: (vpnddcate
				:type (bool)
				:val (false)
			)
			: (ip_pool_securemote
				:type (bool)
				:val (false)
			)
			: (ip_pool_gw2gw
				:type (bool)
				:val (false)
			)
			: (save_data_conns
				:type (bool)
				:val (false)
			)
			: (save_control_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_unused_return_interval
				:type (int)
				:val (60)
			)
			: (fw_keep_old_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_exhaust_ret_interval
				:type (int)
				:val (30)
			)
			: (fw_hmem_size
				:type (int)
				:val (6)
			)
			: (fw_hmem_maxsize
				:type (int)
				:val (30)
			)
			: (connections_limit
				:type (int)
				:val (25000)
			)
			: (connections_hashsize
				:type (int)
				:val (32768)
			)
			: (non_tcp_quota_percentage
				:type (int)
				:val (50)
			)
			: (non_tcp_quota_enable
				:type (bool)
				:val (false)
			)
			: (asm_synatk
				:type (bool)
				:val (false)
			)
			: (asm_synatk_timeout
				:type (int)
				:val (5)
			)
			: (asm_synatk_threshold
				:type (int)
				:val (200)
			)
			: (asm_synatk_external_only
				:type (bool)
				:val (true)
			)
			: (asm_synatk_log
				:type (str)
				:val (log)
			)
			: (asm_synatk_log_level
				:type (int)
				:val (1)
			)
			: (translation_cache_limit
				:type (int)
				:val (10000)
			)
			: (translation_cache_expiry
				:type (int)
				:val (1800)
			)
			: (no_nat_cache_service
				:type (bool)
				:val (false)
			)
			: (vpn_cluster_addr
				:type (int)
				:val (0)
			)
			: (availability_mode
				:type (int)
				:val (0)
			)
			: (fw_my_object_ip
				:type (int)
				:val (-1062667894)
			)
			: (vpn_udpencap_port
				:type (int)
				:val (2746)
			)
			: (EnableDecapsulation
				:type (int)
				:val (0)
			)
			: (support_L2TP
				:type (int)
				:val (0)
			)
			: (om_perform_antispoofing
				:type (int)
				:val (0)
			)
			: (tcpt_active
				:type (int)
				:val (0)
			)
			: (vpn_comp_level
				:type (int)
				:val (2)
			)
			: (ipsec_dont_fragment
				:type (int)
				:val (1)
			)
			: (IPSec_TOS_inner
				:type (int)
				:val (0)
			)
			: (IPSec_TOS_outer
				:type (int)
				:val (1)
			)
			: (is_ikehost
				:type (int)
				:val (1)
			)
			: (disable_replay_check
				:type (int)
				:val (0)
			)
			: (cphwd_round_robin
				:type (int)
				:val (0)
			)
			: (enable_OM_with_multiple_IF
				:type (int)
				:val (0)
			)
			: (keep_DF_flag
				:type (int)
				:val (0)
			)
			: (is_extranet_allowed
				:type (int)
				:val (0)
			)
			: (userc_rules_lm
				:type (int)
				:val (50000)
			)
			: (userc_rules_sz
				:type (int)
				:val (65536)
			)
			: (userc_key_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_sz
				:type (int)
				:val (16384)
			)
			: (inbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (inbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (outbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (outbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (MSPI_requests_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_req_connections_lm
				:type (int)
				:val (25000)
			)
			: (IKE_SA_table_lm
				:type (int)
				:val (40400)
			)
			: (IKE_SA_table_sz
				:type (int)
				:val (65536)
			)
			: (cookies_by_peer_lm
				:type (int)
				:val (20000)
			)
			: (cookies_by_peer_sz
				:type (int)
				:val (32768)
			)
			: (peer_by_cookies_lm
				:type (int)
				:val (20000)
			)
			: (peer_by_cookies_sz
				:type (int)
				:val (32768)
			)
			: (IPSEC_userc_dont_trap_table_lm
				:type (int)
				:val (10000)
			)
			: (userc_pending_lm
				:type (int)
				:val (25000)
			)
			: (MSPI_by_methods_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_map_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_new_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_feedback_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (udp_enc_cln_table_lm
				:type (int)
				:val (20000)
			)
			: (udp_enc_cln_table_sz
				:type (int)
				:val (32768)
			)
			: (om_assigned_ips_lm
				:type (int)
				:val (10000)
			)
			: (udp_response_nat_lm
				:type (int)
				:val (10200)
			)
			: (VIN_SA_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (marcipan_ippool_allocated_lm
				:type (int)
				:val (10000)
			)
			: (marcipan_ippool_users_lm
				:type (int)
				:val (10000)
			)
			: (user_auth_groups_lm
				:type (int)
				:val (20000)
			)
			: (user_auth_groups_sz
				:type (int)
				:val (32768)
			)
			: (persistent_tunnels_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_sz
				:type (int)
				:val (16384)
			)
			: (ipalloc_tab_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_tunnels_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_sessions_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_lookup_lm
				:type (int)
				:val (10000)
			)
			: (max_concurrent_vpn_tunnels
				:type (int)
				:val (10000)
			)
			: (max_concurrent_gw_tunnels
				:type (int)
				:val (200)
			)
			: (fwsynatk_method
				:type (int)
				:val (0)
			)
			: (fwsynatk_timeout
				:type (int)
				:val (10)
			)
			: (fwsynatk_max
				:type (int)
				:val (5000)
			)
			: (fwsynatk_warning
				:type (int)
				:val (1)
			)
			: (fw_rst_expired_conn
				:type (bool)
				:val (false)
			)
			: (IPSec_cluster_nat
				:type (int)
				:val (0)
			)
			: (IPSec_main_if_nat
				:type (int)
				:val (0)
			)
			: (IPSec_orig_if_nat
				:type (int)
				:val (1)
			)
		)
		: (192.168.249.166
			: (vpnddcate
				:type (bool)
				:val (false)
			)
			: (ip_pool_securemote
				:type (bool)
				:val (false)
			)
			: (ip_pool_gw2gw
				:type (bool)
				:val (false)
			)
			: (save_data_conns
				:type (bool)
				:val (false)
			)
			: (save_control_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_unused_return_interval
				:type (int)
				:val (60)
			)
			: (fw_keep_old_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_exhaust_ret_interval
				:type (int)
				:val (30)
			)
			: (fw_hmem_size
				:type (int)
				:val (6)
			)
			: (fw_hmem_maxsize
				:type (int)
				:val (30)
			)
			: (connections_limit
				:type (int)
				:val (25000)
			)
			: (connections_hashsize
				:type (int)
				:val (32768)
			)
			: (non_tcp_quota_percentage
				:type (int)
				:val (50)
			)
			: (non_tcp_quota_enable
				:type (bool)
				:val (false)
			)
			: (asm_synatk
				:type (bool)
				:val (false)
			)
			: (asm_synatk_timeout
				:type (int)
				:val (5)
			)
			: (asm_synatk_threshold
				:type (int)
				:val (200)
			)
			: (asm_synatk_external_only
				:type (bool)
				:val (true)
			)
			: (asm_synatk_log
				:type (str)
				:val (log)
			)
			: (asm_synatk_log_level
				:type (int)
				:val (1)
			)
			: (translation_cache_limit
				:type (int)
				:val (10000)
			)
			: (translation_cache_expiry
				:type (int)
				:val (1800)
			)
			: (no_nat_cache_service
				:type (bool)
				:val (false)
			)
			: (vpn_cluster_addr
				:type (int)
				:val (0)
			)
			: (availability_mode
				:type (int)
				:val (0)
			)
			: (fw_my_object_ip
				:type (int)
				:val (-1062667866)
			)
			: (vpn_udpencap_port
				:type (int)
				:val (2746)
			)
			: (EnableDecapsulation
				:type (int)
				:val (0)
			)
			: (support_L2TP
				:type (int)
				:val (0)
			)
			: (om_perform_antispoofing
				:type (int)
				:val (0)
			)
			: (tcpt_active
				:type (int)
				:val (0)
			)
			: (vpn_comp_level
				:type (int)
				:val (2)
			)
			: (ipsec_dont_fragment
				:type (int)
				:val (1)
			)
			: (IPSec_TOS_inner
				:type (int)
				:val (0)
			)
			: (IPSec_TOS_outer
				:type (int)
				:val (1)
			)
			: (is_ikehost
				:type (int)
				:val (1)
			)
			: (disable_replay_check
				:type (int)
				:val (0)
			)
			: (cphwd_round_robin
				:type (int)
				:val (0)
			)
			: (enable_OM_with_multiple_IF
				:type (int)
				:val (0)
			)
			: (keep_DF_flag
				:type (int)
				:val (0)
			)
			: (is_extranet_allowed
				:type (int)
				:val (0)
			)
			: (userc_rules_lm
				:type (int)
				:val (50000)
			)
			: (userc_rules_sz
				:type (int)
				:val (65536)
			)
			: (userc_key_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_sz
				:type (int)
				:val (16384)
			)
			: (inbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (inbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (outbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (outbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (MSPI_requests_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_req_connections_lm
				:type (int)
				:val (25000)
			)
			: (IKE_SA_table_lm
				:type (int)
				:val (40400)
			)
			: (IKE_SA_table_sz
				:type (int)
				:val (65536)
			)
			: (cookies_by_peer_lm
				:type (int)
				:val (20000)
			)
			: (cookies_by_peer_sz
				:type (int)
				:val (32768)
			)
			: (peer_by_cookies_lm
				:type (int)
				:val (20000)
			)
			: (peer_by_cookies_sz
				:type (int)
				:val (32768)
			)
			: (IPSEC_userc_dont_trap_table_lm
				:type (int)
				:val (10000)
			)
			: (userc_pending_lm
				:type (int)
				:val (25000)
			)
			: (MSPI_by_methods_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_map_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_new_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_feedback_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (udp_enc_cln_table_lm
				:type (int)
				:val (20000)
			)
			: (udp_enc_cln_table_sz
				:type (int)
				:val (32768)
			)
			: (om_assigned_ips_lm
				:type (int)
				:val (10000)
			)
			: (udp_response_nat_lm
				:type (int)
				:val (10200)
			)
			: (VIN_SA_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (marcipan_ippool_allocated_lm
				:type (int)
				:val (10000)
			)
			: (marcipan_ippool_users_lm
				:type (int)
				:val (10000)
			)
			: (user_auth_groups_lm
				:type (int)
				:val (20000)
			)
			: (user_auth_groups_sz
				:type (int)
				:val (32768)
			)
			: (persistent_tunnels_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_sz
				:type (int)
				:val (16384)
			)
			: (ipalloc_tab_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_tunnels_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_sessions_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_lookup_lm
				:type (int)
				:val (10000)
			)
			: (max_concurrent_vpn_tunnels
				:type (int)
				:val (10000)
			)
			: (max_concurrent_gw_tunnels
				:type (int)
				:val (200)
			)
			: (fwsynatk_method
				:type (int)
				:val (0)
			)
			: (fwsynatk_timeout
				:type (int)
				:val (10)
			)
			: (fwsynatk_max
				:type (int)
				:val (5000)
			)
			: (fwsynatk_warning
				:type (int)
				:val (1)
			)
			: (fw_rst_expired_conn
				:type (bool)
				:val (false)
			)
			: (IPSec_cluster_nat
				:type (int)
				:val (0)
			)
			: (IPSec_main_if_nat
				:type (int)
				:val (0)
			)
			: (IPSec_orig_if_nat
				:type (int)
				:val (1)
			)
		)
		: (192.168.249.146
			: (vpnddcate
				:type (bool)
				:val (false)
			)
			: (ip_pool_securemote
				:type (bool)
				:val (false)
			)
			: (ip_pool_gw2gw
				:type (bool)
				:val (false)
			)
			: (save_data_conns
				:type (bool)
				:val (false)
			)
			: (save_control_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_unused_return_interval
				:type (int)
				:val (60)
			)
			: (fw_keep_old_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_exhaust_ret_interval
				:type (int)
				:val (30)
			)
			: (fw_hmem_size
				:type (int)
				:val (6)
			)
			: (fw_hmem_maxsize
				:type (int)
				:val (30)
			)
			: (connections_limit
				:type (int)
				:val (25000)
			)
			: (connections_hashsize
				:type (int)
				:val (32768)
			)
			: (non_tcp_quota_percentage
				:type (int)
				:val (50)
			)
			: (non_tcp_quota_enable
				:type (bool)
				:val (false)
			)
			: (asm_synatk
				:type (bool)
				:val (false)
			)
			: (asm_synatk_timeout
				:type (int)
				:val (5)
			)
			: (asm_synatk_threshold
				:type (int)
				:val (200)
			)
			: (asm_synatk_external_only
				:type (bool)
				:val (true)
			)
			: (asm_synatk_log
				:type (str)
				:val (log)
			)
			: (asm_synatk_log_level
				:type (int)
				:val (1)
			)
			: (translation_cache_limit
				:type (int)
				:val (10000)
			)
			: (translation_cache_expiry
				:type (int)
				:val (1800)
			)
			: (no_nat_cache_service
				:type (bool)
				:val (false)
			)
			: (vpn_cluster_addr
				:type (int)
				:val (0)
			)
			: (availability_mode
				:type (int)
				:val (0)
			)
			: (fw_my_object_ip
				:type (int)
				:val (-1062667886)
			)
			: (vpn_udpencap_port
				:type (int)
				:val (2746)
			)
			: (EnableDecapsulation
				:type (int)
				:val (0)
			)
			: (support_L2TP
				:type (int)
				:val (0)
			)
			: (om_perform_antispoofing
				:type (int)
				:val (0)
			)
			: (tcpt_active
				:type (int)
				:val (0)
			)
			: (vpn_comp_level
				:type (int)
				:val (2)
			)
			: (ipsec_dont_fragment
				:type (int)
				:val (1)
			)
			: (IPSec_TOS_inner
				:type (int)
				:val (0)
			)
			: (IPSec_TOS_outer
				:type (int)
				:val (1)
			)
			: (is_ikehost
				:type (int)
				:val (1)
			)
			: (disable_replay_check
				:type (int)
				:val (0)
			)
			: (cphwd_round_robin
				:type (int)
				:val (0)
			)
			: (enable_OM_with_multiple_IF
				:type (int)
				:val (0)
			)
			: (keep_DF_flag
				:type (int)
				:val (0)
			)
			: (is_extranet_allowed
				:type (int)
				:val (0)
			)
			: (userc_rules_lm
				:type (int)
				:val (50000)
			)
			: (userc_rules_sz
				:type (int)
				:val (65536)
			)
			: (userc_key_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_sz
				:type (int)
				:val (16384)
			)
			: (inbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (inbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (outbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (outbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (MSPI_requests_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_req_connections_lm
				:type (int)
				:val (25000)
			)
			: (IKE_SA_table_lm
				:type (int)
				:val (40400)
			)
			: (IKE_SA_table_sz
				:type (int)
				:val (65536)
			)
			: (cookies_by_peer_lm
				:type (int)
				:val (20000)
			)
			: (cookies_by_peer_sz
				:type (int)
				:val (32768)
			)
			: (peer_by_cookies_lm
				:type (int)
				:val (20000)
			)
			: (peer_by_cookies_sz
				:type (int)
				:val (32768)
			)
			: (IPSEC_userc_dont_trap_table_lm
				:type (int)
				:val (10000)
			)
			: (userc_pending_lm
				:type (int)
				:val (25000)
			)
			: (MSPI_by_methods_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_map_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_new_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_feedback_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (udp_enc_cln_table_lm
				:type (int)
				:val (20000)
			)
			: (udp_enc_cln_table_sz
				:type (int)
				:val (32768)
			)
			: (om_assigned_ips_lm
				:type (int)
				:val (10000)
			)
			: (udp_response_nat_lm
				:type (int)
				:val (10200)
			)
			: (VIN_SA_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (marcipan_ippool_allocated_lm
				:type (int)
				:val (10000)
			)
			: (marcipan_ippool_users_lm
				:type (int)
				:val (10000)
			)
			: (user_auth_groups_lm
				:type (int)
				:val (20000)
			)
			: (user_auth_groups_sz
				:type (int)
				:val (32768)
			)
			: (persistent_tunnels_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_sz
				:type (int)
				:val (16384)
			)
			: (ipalloc_tab_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_tunnels_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_sessions_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_lookup_lm
				:type (int)
				:val (10000)
			)
			: (max_concurrent_vpn_tunnels
				:type (int)
				:val (10000)
			)
			: (max_concurrent_gw_tunnels
				:type (int)
				:val (200)
			)
			: (fwsynatk_method
				:type (int)
				:val (0)
			)
			: (fwsynatk_timeout
				:type (int)
				:val (10)
			)
			: (fwsynatk_max
				:type (int)
				:val (5000)
			)
			: (fwsynatk_warning
				:type (int)
				:val (1)
			)
			: (fw_rst_expired_conn
				:type (bool)
				:val (false)
			)
			: (IPSec_cluster_nat
				:type (int)
				:val (0)
			)
			: (IPSec_main_if_nat
				:type (int)
				:val (0)
			)
			: (IPSec_orig_if_nat
				:type (int)
				:val (1)
			)
		)
		: (192.168.249.154
			: (vpnddcate
				:type (bool)
				:val (false)
			)
			: (ip_pool_securemote
				:type (bool)
				:val (false)
			)
			: (ip_pool_gw2gw
				:type (bool)
				:val (false)
			)
			: (save_data_conns
				:type (bool)
				:val (false)
			)
			: (save_control_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_unused_return_interval
				:type (int)
				:val (60)
			)
			: (fw_keep_old_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_exhaust_ret_interval
				:type (int)
				:val (30)
			)
			: (fw_hmem_size
				:type (int)
				:val (6)
			)
			: (fw_hmem_maxsize
				:type (int)
				:val (30)
			)
			: (connections_limit
				:type (int)
				:val (25000)
			)
			: (connections_hashsize
				:type (int)
				:val (32768)
			)
			: (non_tcp_quota_percentage
				:type (int)
				:val (50)
			)
			: (non_tcp_quota_enable
				:type (bool)
				:val (false)
			)
			: (asm_synatk
				:type (bool)
				:val (false)
			)
			: (asm_synatk_timeout
				:type (int)
				:val (5)
			)
			: (asm_synatk_threshold
				:type (int)
				:val (200)
			)
			: (asm_synatk_external_only
				:type (bool)
				:val (true)
			)
			: (asm_synatk_log
				:type (str)
				:val (log)
			)
			: (asm_synatk_log_level
				:type (int)
				:val (1)
			)
			: (translation_cache_limit
				:type (int)
				:val (10000)
			)
			: (translation_cache_expiry
				:type (int)
				:val (1800)
			)
			: (no_nat_cache_service
				:type (bool)
				:val (false)
			)
			: (vpn_cluster_addr
				:type (int)
				:val (0)
			)
			: (availability_mode
				:type (int)
				:val (0)
			)
			: (fw_my_object_ip
				:type (int)
				:val (-1062667878)
			)
			: (vpn_udpencap_port
				:type (int)
				:val (2746)
			)
			: (EnableDecapsulation
				:type (int)
				:val (0)
			)
			: (support_L2TP
				:type (int)
				:val (0)
			)
			: (om_perform_antispoofing
				:type (int)
				:val (0)
			)
			: (tcpt_active
				:type (int)
				:val (0)
			)
			: (vpn_comp_level
				:type (int)
				:val (2)
			)
			: (ipsec_dont_fragment
				:type (int)
				:val (1)
			)
			: (IPSec_TOS_inner
				:type (int)
				:val (0)
			)
			: (IPSec_TOS_outer
				:type (int)
				:val (1)
			)
			: (is_ikehost
				:type (int)
				:val (1)
			)
			: (disable_replay_check
				:type (int)
				:val (0)
			)
			: (cphwd_round_robin
				:type (int)
				:val (0)
			)
			: (enable_OM_with_multiple_IF
				:type (int)
				:val (0)
			)
			: (keep_DF_flag
				:type (int)
				:val (0)
			)
			: (is_extranet_allowed
				:type (int)
				:val (0)
			)
			: (userc_rules_lm
				:type (int)
				:val (50000)
			)
			: (userc_rules_sz
				:type (int)
				:val (65536)
			)
			: (userc_key_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_sz
				:type (int)
				:val (16384)
			)
			: (inbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (inbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (outbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (outbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (MSPI_requests_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_req_connections_lm
				:type (int)
				:val (25000)
			)
			: (IKE_SA_table_lm
				:type (int)
				:val (40400)
			)
			: (IKE_SA_table_sz
				:type (int)
				:val (65536)
			)
			: (cookies_by_peer_lm
				:type (int)
				:val (20000)
			)
			: (cookies_by_peer_sz
				:type (int)
				:val (32768)
			)
			: (peer_by_cookies_lm
				:type (int)
				:val (20000)
			)
			: (peer_by_cookies_sz
				:type (int)
				:val (32768)
			)
			: (IPSEC_userc_dont_trap_table_lm
				:type (int)
				:val (10000)
			)
			: (userc_pending_lm
				:type (int)
				:val (25000)
			)
			: (MSPI_by_methods_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_map_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_new_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_feedback_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (udp_enc_cln_table_lm
				:type (int)
				:val (20000)
			)
			: (udp_enc_cln_table_sz
				:type (int)
				:val (32768)
			)
			: (om_assigned_ips_lm
				:type (int)
				:val (10000)
			)
			: (udp_response_nat_lm
				:type (int)
				:val (10200)
			)
			: (VIN_SA_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (marcipan_ippool_allocated_lm
				:type (int)
				:val (10000)
			)
			: (marcipan_ippool_users_lm
				:type (int)
				:val (10000)
			)
			: (user_auth_groups_lm
				:type (int)
				:val (20000)
			)
			: (user_auth_groups_sz
				:type (int)
				:val (32768)
			)
			: (persistent_tunnels_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_sz
				:type (int)
				:val (16384)
			)
			: (ipalloc_tab_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_tunnels_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_sessions_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_lookup_lm
				:type (int)
				:val (10000)
			)
			: (max_concurrent_vpn_tunnels
				:type (int)
				:val (10000)
			)
			: (max_concurrent_gw_tunnels
				:type (int)
				:val (200)
			)
			: (fwsynatk_method
				:type (int)
				:val (0)
			)
			: (fwsynatk_timeout
				:type (int)
				:val (10)
			)
			: (fwsynatk_max
				:type (int)
				:val (5000)
			)
			: (fwsynatk_warning
				:type (int)
				:val (1)
			)
			: (fw_rst_expired_conn
				:type (bool)
				:val (false)
			)
			: (IPSec_cluster_nat
				:type (int)
				:val (0)
			)
			: (IPSec_main_if_nat
				:type (int)
				:val (0)
			)
			: (IPSec_orig_if_nat
				:type (int)
				:val (1)
			)
		)
		: (192.168.249.142
			: (vpnddcate
				:type (bool)
				:val (false)
			)
			: (ip_pool_securemote
				:type (bool)
				:val (false)
			)
			: (ip_pool_gw2gw
				:type (bool)
				:val (false)
			)
			: (save_data_conns
				:type (bool)
				:val (false)
			)
			: (save_control_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_unused_return_interval
				:type (int)
				:val (60)
			)
			: (fw_keep_old_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_exhaust_ret_interval
				:type (int)
				:val (30)
			)
			: (fw_hmem_size
				:type (int)
				:val (6)
			)
			: (fw_hmem_maxsize
				:type (int)
				:val (30)
			)
			: (connections_limit
				:type (int)
				:val (25000)
			)
			: (connections_hashsize
				:type (int)
				:val (32768)
			)
			: (non_tcp_quota_percentage
				:type (int)
				:val (50)
			)
			: (non_tcp_quota_enable
				:type (bool)
				:val (false)
			)
			: (asm_synatk
				:type (bool)
				:val (false)
			)
			: (asm_synatk_timeout
				:type (int)
				:val (5)
			)
			: (asm_synatk_threshold
				:type (int)
				:val (200)
			)
			: (asm_synatk_external_only
				:type (bool)
				:val (true)
			)
			: (asm_synatk_log
				:type (str)
				:val (log)
			)
			: (asm_synatk_log_level
				:type (int)
				:val (1)
			)
			: (translation_cache_limit
				:type (int)
				:val (10000)
			)
			: (translation_cache_expiry
				:type (int)
				:val (1800)
			)
			: (no_nat_cache_service
				:type (bool)
				:val (false)
			)
			: (vpn_cluster_addr
				:type (int)
				:val (0)
			)
			: (availability_mode
				:type (int)
				:val (0)
			)
			: (fw_my_object_ip
				:type (int)
				:val (-1062667890)
			)
			: (vpn_udpencap_port
				:type (int)
				:val (2746)
			)
			: (EnableDecapsulation
				:type (int)
				:val (0)
			)
			: (support_L2TP
				:type (int)
				:val (0)
			)
			: (om_perform_antispoofing
				:type (int)
				:val (0)
			)
			: (tcpt_active
				:type (int)
				:val (0)
			)
			: (vpn_comp_level
				:type (int)
				:val (2)
			)
			: (ipsec_dont_fragment
				:type (int)
				:val (1)
			)
			: (IPSec_TOS_inner
				:type (int)
				:val (0)
			)
			: (IPSec_TOS_outer
				:type (int)
				:val (1)
			)
			: (is_ikehost
				:type (int)
				:val (1)
			)
			: (disable_replay_check
				:type (int)
				:val (0)
			)
			: (cphwd_round_robin
				:type (int)
				:val (0)
			)
			: (enable_OM_with_multiple_IF
				:type (int)
				:val (0)
			)
			: (keep_DF_flag
				:type (int)
				:val (0)
			)
			: (is_extranet_allowed
				:type (int)
				:val (0)
			)
			: (userc_rules_lm
				:type (int)
				:val (50000)
			)
			: (userc_rules_sz
				:type (int)
				:val (65536)
			)
			: (userc_key_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_sz
				:type (int)
				:val (16384)
			)
			: (inbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (inbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (outbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (outbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (MSPI_requests_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_req_connections_lm
				:type (int)
				:val (25000)
			)
			: (IKE_SA_table_lm
				:type (int)
				:val (40400)
			)
			: (IKE_SA_table_sz
				:type (int)
				:val (65536)
			)
			: (cookies_by_peer_lm
				:type (int)
				:val (20000)
			)
			: (cookies_by_peer_sz
				:type (int)
				:val (32768)
			)
			: (peer_by_cookies_lm
				:type (int)
				:val (20000)
			)
			: (peer_by_cookies_sz
				:type (int)
				:val (32768)
			)
			: (IPSEC_userc_dont_trap_table_lm
				:type (int)
				:val (10000)
			)
			: (userc_pending_lm
				:type (int)
				:val (25000)
			)
			: (MSPI_by_methods_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_map_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_new_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_feedback_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (udp_enc_cln_table_lm
				:type (int)
				:val (20000)
			)
			: (udp_enc_cln_table_sz
				:type (int)
				:val (32768)
			)
			: (om_assigned_ips_lm
				:type (int)
				:val (10000)
			)
			: (udp_response_nat_lm
				:type (int)
				:val (10200)
			)
			: (VIN_SA_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (marcipan_ippool_allocated_lm
				:type (int)
				:val (10000)
			)
			: (marcipan_ippool_users_lm
				:type (int)
				:val (10000)
			)
			: (user_auth_groups_lm
				:type (int)
				:val (20000)
			)
			: (user_auth_groups_sz
				:type (int)
				:val (32768)
			)
			: (persistent_tunnels_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_sz
				:type (int)
				:val (16384)
			)
			: (ipalloc_tab_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_tunnels_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_sessions_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_lookup_lm
				:type (int)
				:val (10000)
			)
			: (max_concurrent_vpn_tunnels
				:type (int)
				:val (10000)
			)
			: (max_concurrent_gw_tunnels
				:type (int)
				:val (200)
			)
			: (fwsynatk_method
				:type (int)
				:val (0)
			)
			: (fwsynatk_timeout
				:type (int)
				:val (10)
			)
			: (fwsynatk_max
				:type (int)
				:val (5000)
			)
			: (fwsynatk_warning
				:type (int)
				:val (1)
			)
			: (fw_rst_expired_conn
				:type (bool)
				:val (false)
			)
			: (IPSec_cluster_nat
				:type (int)
				:val (0)
			)
			: (IPSec_main_if_nat
				:type (int)
				:val (0)
			)
			: (IPSec_orig_if_nat
				:type (int)
				:val (1)
			)
		)
		: (192.168.249.158
			: (vpnddcate
				:type (bool)
				:val (false)
			)
			: (ip_pool_securemote
				:type (bool)
				:val (false)
			)
			: (ip_pool_gw2gw
				:type (bool)
				:val (false)
			)
			: (save_data_conns
				:type (bool)
				:val (false)
			)
			: (save_control_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_unused_return_interval
				:type (int)
				:val (60)
			)
			: (fw_keep_old_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_exhaust_ret_interval
				:type (int)
				:val (30)
			)
			: (fw_hmem_size
				:type (int)
				:val (6)
			)
			: (fw_hmem_maxsize
				:type (int)
				:val (30)
			)
			: (connections_limit
				:type (int)
				:val (25000)
			)
			: (connections_hashsize
				:type (int)
				:val (32768)
			)
			: (non_tcp_quota_percentage
				:type (int)
				:val (50)
			)
			: (non_tcp_quota_enable
				:type (bool)
				:val (false)
			)
			: (asm_synatk
				:type (bool)
				:val (false)
			)
			: (asm_synatk_timeout
				:type (int)
				:val (5)
			)
			: (asm_synatk_threshold
				:type (int)
				:val (200)
			)
			: (asm_synatk_external_only
				:type (bool)
				:val (true)
			)
			: (asm_synatk_log
				:type (str)
				:val (log)
			)
			: (asm_synatk_log_level
				:type (int)
				:val (1)
			)
			: (translation_cache_limit
				:type (int)
				:val (10000)
			)
			: (translation_cache_expiry
				:type (int)
				:val (1800)
			)
			: (no_nat_cache_service
				:type (bool)
				:val (false)
			)
			: (vpn_cluster_addr
				:type (int)
				:val (0)
			)
			: (availability_mode
				:type (int)
				:val (0)
			)
			: (fw_my_object_ip
				:type (int)
				:val (-1062667874)
			)
			: (vpn_udpencap_port
				:type (int)
				:val (2746)
			)
			: (EnableDecapsulation
				:type (int)
				:val (0)
			)
			: (support_L2TP
				:type (int)
				:val (0)
			)
			: (om_perform_antispoofing
				:type (int)
				:val (0)
			)
			: (tcpt_active
				:type (int)
				:val (0)
			)
			: (vpn_comp_level
				:type (int)
				:val (2)
			)
			: (ipsec_dont_fragment
				:type (int)
				:val (1)
			)
			: (IPSec_TOS_inner
				:type (int)
				:val (0)
			)
			: (IPSec_TOS_outer
				:type (int)
				:val (1)
			)
			: (is_ikehost
				:type (int)
				:val (1)
			)
			: (disable_replay_check
				:type (int)
				:val (0)
			)
			: (cphwd_round_robin
				:type (int)
				:val (0)
			)
			: (enable_OM_with_multiple_IF
				:type (int)
				:val (0)
			)
			: (keep_DF_flag
				:type (int)
				:val (0)
			)
			: (is_extranet_allowed
				:type (int)
				:val (0)
			)
			: (userc_rules_lm
				:type (int)
				:val (50000)
			)
			: (userc_rules_sz
				:type (int)
				:val (65536)
			)
			: (userc_key_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_sz
				:type (int)
				:val (16384)
			)
			: (inbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (inbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (outbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (outbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (MSPI_requests_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_req_connections_lm
				:type (int)
				:val (25000)
			)
			: (IKE_SA_table_lm
				:type (int)
				:val (40400)
			)
			: (IKE_SA_table_sz
				:type (int)
				:val (65536)
			)
			: (cookies_by_peer_lm
				:type (int)
				:val (20000)
			)
			: (cookies_by_peer_sz
				:type (int)
				:val (32768)
			)
			: (peer_by_cookies_lm
				:type (int)
				:val (20000)
			)
			: (peer_by_cookies_sz
				:type (int)
				:val (32768)
			)
			: (IPSEC_userc_dont_trap_table_lm
				:type (int)
				:val (10000)
			)
			: (userc_pending_lm
				:type (int)
				:val (25000)
			)
			: (MSPI_by_methods_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_map_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_new_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_feedback_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (udp_enc_cln_table_lm
				:type (int)
				:val (20000)
			)
			: (udp_enc_cln_table_sz
				:type (int)
				:val (32768)
			)
			: (om_assigned_ips_lm
				:type (int)
				:val (10000)
			)
			: (udp_response_nat_lm
				:type (int)
				:val (10200)
			)
			: (VIN_SA_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (marcipan_ippool_allocated_lm
				:type (int)
				:val (10000)
			)
			: (marcipan_ippool_users_lm
				:type (int)
				:val (10000)
			)
			: (user_auth_groups_lm
				:type (int)
				:val (20000)
			)
			: (user_auth_groups_sz
				:type (int)
				:val (32768)
			)
			: (persistent_tunnels_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_sz
				:type (int)
				:val (16384)
			)
			: (ipalloc_tab_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_tunnels_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_sessions_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_lookup_lm
				:type (int)
				:val (10000)
			)
			: (max_concurrent_vpn_tunnels
				:type (int)
				:val (10000)
			)
			: (max_concurrent_gw_tunnels
				:type (int)
				:val (200)
			)
			: (fwsynatk_method
				:type (int)
				:val (0)
			)
			: (fwsynatk_timeout
				:type (int)
				:val (10)
			)
			: (fwsynatk_max
				:type (int)
				:val (5000)
			)
			: (fwsynatk_warning
				:type (int)
				:val (1)
			)
			: (fw_rst_expired_conn
				:type (bool)
				:val (false)
			)
			: (IPSec_cluster_nat
				:type (int)
				:val (0)
			)
			: (IPSec_main_if_nat
				:type (int)
				:val (0)
			)
			: (IPSec_orig_if_nat
				:type (int)
				:val (1)
			)
		)
		: (192.168.249.162
			: (vpnddcate
				:type (bool)
				:val (false)
			)
			: (ip_pool_securemote
				:type (bool)
				:val (false)
			)
			: (ip_pool_gw2gw
				:type (bool)
				:val (false)
			)
			: (save_data_conns
				:type (bool)
				:val (false)
			)
			: (save_control_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_unused_return_interval
				:type (int)
				:val (60)
			)
			: (fw_keep_old_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_exhaust_ret_interval
				:type (int)
				:val (30)
			)
			: (fw_hmem_size
				:type (int)
				:val (6)
			)
			: (fw_hmem_maxsize
				:type (int)
				:val (30)
			)
			: (connections_limit
				:type (int)
				:val (25000)
			)
			: (connections_hashsize
				:type (int)
				:val (32768)
			)
			: (non_tcp_quota_percentage
				:type (int)
				:val (50)
			)
			: (non_tcp_quota_enable
				:type (bool)
				:val (false)
			)
			: (asm_synatk
				:type (bool)
				:val (false)
			)
			: (asm_synatk_timeout
				:type (int)
				:val (5)
			)
			: (asm_synatk_threshold
				:type (int)
				:val (200)
			)
			: (asm_synatk_external_only
				:type (bool)
				:val (true)
			)
			: (asm_synatk_log
				:type (str)
				:val (log)
			)
			: (asm_synatk_log_level
				:type (int)
				:val (1)
			)
			: (translation_cache_limit
				:type (int)
				:val (10000)
			)
			: (translation_cache_expiry
				:type (int)
				:val (1800)
			)
			: (no_nat_cache_service
				:type (bool)
				:val (false)
			)
			: (vpn_cluster_addr
				:type (int)
				:val (0)
			)
			: (availability_mode
				:type (int)
				:val (0)
			)
			: (fw_my_object_ip
				:type (int)
				:val (-1062667870)
			)
			: (vpn_udpencap_port
				:type (int)
				:val (2746)
			)
			: (EnableDecapsulation
				:type (int)
				:val (0)
			)
			: (support_L2TP
				:type (int)
				:val (0)
			)
			: (om_perform_antispoofing
				:type (int)
				:val (0)
			)
			: (tcpt_active
				:type (int)
				:val (0)
			)
			: (vpn_comp_level
				:type (int)
				:val (2)
			)
			: (ipsec_dont_fragment
				:type (int)
				:val (1)
			)
			: (IPSec_TOS_inner
				:type (int)
				:val (0)
			)
			: (IPSec_TOS_outer
				:type (int)
				:val (1)
			)
			: (is_ikehost
				:type (int)
				:val (1)
			)
			: (disable_replay_check
				:type (int)
				:val (0)
			)
			: (cphwd_round_robin
				:type (int)
				:val (0)
			)
			: (enable_OM_with_multiple_IF
				:type (int)
				:val (0)
			)
			: (keep_DF_flag
				:type (int)
				:val (0)
			)
			: (is_extranet_allowed
				:type (int)
				:val (0)
			)
			: (userc_rules_lm
				:type (int)
				:val (50000)
			)
			: (userc_rules_sz
				:type (int)
				:val (65536)
			)
			: (userc_key_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_sz
				:type (int)
				:val (16384)
			)
			: (inbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (inbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (outbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (outbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (MSPI_requests_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_req_connections_lm
				:type (int)
				:val (25000)
			)
			: (IKE_SA_table_lm
				:type (int)
				:val (40400)
			)
			: (IKE_SA_table_sz
				:type (int)
				:val (65536)
			)
			: (cookies_by_peer_lm
				:type (int)
				:val (20000)
			)
			: (cookies_by_peer_sz
				:type (int)
				:val (32768)
			)
			: (peer_by_cookies_lm
				:type (int)
				:val (20000)
			)
			: (peer_by_cookies_sz
				:type (int)
				:val (32768)
			)
			: (IPSEC_userc_dont_trap_table_lm
				:type (int)
				:val (10000)
			)
			: (userc_pending_lm
				:type (int)
				:val (25000)
			)
			: (MSPI_by_methods_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_map_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_new_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_feedback_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (udp_enc_cln_table_lm
				:type (int)
				:val (20000)
			)
			: (udp_enc_cln_table_sz
				:type (int)
				:val (32768)
			)
			: (om_assigned_ips_lm
				:type (int)
				:val (10000)
			)
			: (udp_response_nat_lm
				:type (int)
				:val (10200)
			)
			: (VIN_SA_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (marcipan_ippool_allocated_lm
				:type (int)
				:val (10000)
			)
			: (marcipan_ippool_users_lm
				:type (int)
				:val (10000)
			)
			: (user_auth_groups_lm
				:type (int)
				:val (20000)
			)
			: (user_auth_groups_sz
				:type (int)
				:val (32768)
			)
			: (persistent_tunnels_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_sz
				:type (int)
				:val (16384)
			)
			: (ipalloc_tab_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_tunnels_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_sessions_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_lookup_lm
				:type (int)
				:val (10000)
			)
			: (max_concurrent_vpn_tunnels
				:type (int)
				:val (10000)
			)
			: (max_concurrent_gw_tunnels
				:type (int)
				:val (200)
			)
			: (fwsynatk_method
				:type (int)
				:val (0)
			)
			: (fwsynatk_timeout
				:type (int)
				:val (10)
			)
			: (fwsynatk_max
				:type (int)
				:val (5000)
			)
			: (fwsynatk_warning
				:type (int)
				:val (1)
			)
			: (fw_rst_expired_conn
				:type (bool)
				:val (false)
			)
			: (IPSec_cluster_nat
				:type (int)
				:val (0)
			)
			: (IPSec_main_if_nat
				:type (int)
				:val (0)
			)
			: (IPSec_orig_if_nat
				:type (int)
				:val (1)
			)
		)
		: (196.192.44.5
			: (vpnddcate
				:type (bool)
				:val (false)
			)
			: (ip_pool_securemote
				:type (bool)
				:val (false)
			)
			: (ip_pool_gw2gw
				:type (bool)
				:val (false)
			)
			: (save_data_conns
				:type (bool)
				:val (false)
			)
			: (save_control_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_unused_return_interval
				:type (int)
				:val (60)
			)
			: (fw_keep_old_conns
				:type (bool)
				:val (false)
			)
			: (ip_pool_exhaust_ret_interval
				:type (int)
				:val (30)
			)
			: (fw_hmem_size
				:type (int)
				:val (6)
			)
			: (fw_hmem_maxsize
				:type (int)
				:val (30)
			)
			: (connections_limit
				:type (int)
				:val (25000)
			)
			: (connections_hashsize
				:type (int)
				:val (32768)
			)
			: (non_tcp_quota_percentage
				:type (int)
				:val (50)
			)
			: (non_tcp_quota_enable
				:type (bool)
				:val (false)
			)
			: (asm_synatk
				:type (bool)
				:val (false)
			)
			: (asm_synatk_timeout
				:type (int)
				:val (5)
			)
			: (asm_synatk_threshold
				:type (int)
				:val (200)
			)
			: (asm_synatk_external_only
				:type (bool)
				:val (true)
			)
			: (asm_synatk_log
				:type (str)
				:val (log)
			)
			: (asm_synatk_log_level
				:type (int)
				:val (1)
			)
			: (translation_cache_limit
				:type (int)
				:val (10000)
			)
			: (translation_cache_expiry
				:type (int)
				:val (1800)
			)
			: (no_nat_cache_service
				:type (bool)
				:val (false)
			)
			: (vpn_cluster_addr
				:type (int)
				:val (0)
			)
			: (availability_mode
				:type (int)
				:val (0)
			)
			: (fw_my_object_ip
				:type (int)
				:val (-994038779)
			)
			: (vpn_udpencap_port
				:type (int)
				:val (2746)
			)
			: (EnableDecapsulation
				:type (int)
				:val (0)
			)
			: (support_L2TP
				:type (int)
				:val (0)
			)
			: (om_perform_antispoofing
				:type (int)
				:val (0)
			)
			: (tcpt_active
				:type (int)
				:val (0)
			)
			: (vpn_comp_level
				:type (int)
				:val (2)
			)
			: (ipsec_dont_fragment
				:type (int)
				:val (1)
			)
			: (IPSec_TOS_inner
				:type (int)
				:val (0)
			)
			: (IPSec_TOS_outer
				:type (int)
				:val (1)
			)
			: (is_ikehost
				:type (int)
				:val (1)
			)
			: (disable_replay_check
				:type (int)
				:val (0)
			)
			: (cphwd_round_robin
				:type (int)
				:val (0)
			)
			: (enable_OM_with_multiple_IF
				:type (int)
				:val (0)
			)
			: (keep_DF_flag
				:type (int)
				:val (0)
			)
			: (is_extranet_allowed
				:type (int)
				:val (0)
			)
			: (userc_rules_lm
				:type (int)
				:val (50000)
			)
			: (userc_rules_sz
				:type (int)
				:val (65536)
			)
			: (userc_key_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_lm
				:type (int)
				:val (10000)
			)
			: (userc_users_sz
				:type (int)
				:val (16384)
			)
			: (inbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (inbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (outbound_SPI_lm
				:type (int)
				:val (20400)
			)
			: (outbound_SPI_sz
				:type (int)
				:val (32768)
			)
			: (MSPI_requests_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_req_connections_lm
				:type (int)
				:val (25000)
			)
			: (IKE_SA_table_lm
				:type (int)
				:val (40400)
			)
			: (IKE_SA_table_sz
				:type (int)
				:val (65536)
			)
			: (cookies_by_peer_lm
				:type (int)
				:val (20000)
			)
			: (cookies_by_peer_sz
				:type (int)
				:val (32768)
			)
			: (peer_by_cookies_lm
				:type (int)
				:val (20000)
			)
			: (peer_by_cookies_sz
				:type (int)
				:val (32768)
			)
			: (IPSEC_userc_dont_trap_table_lm
				:type (int)
				:val (10000)
			)
			: (userc_pending_lm
				:type (int)
				:val (25000)
			)
			: (MSPI_by_methods_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_map_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_feedback_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_feedback_new_lm
				:type (int)
				:val (10200)
			)
			: (L2TP_MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_cluster_update_lm
				:type (int)
				:val (10200)
			)
			: (MSPI_feedback_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (udp_enc_cln_table_lm
				:type (int)
				:val (20000)
			)
			: (udp_enc_cln_table_sz
				:type (int)
				:val (32768)
			)
			: (om_assigned_ips_lm
				:type (int)
				:val (10000)
			)
			: (udp_response_nat_lm
				:type (int)
				:val (10200)
			)
			: (VIN_SA_to_delete_lm
				:type (int)
				:val (10200)
			)
			: (marcipan_ippool_allocated_lm
				:type (int)
				:val (10000)
			)
			: (marcipan_ippool_users_lm
				:type (int)
				:val (10000)
			)
			: (user_auth_groups_lm
				:type (int)
				:val (20000)
			)
			: (user_auth_groups_sz
				:type (int)
				:val (32768)
			)
			: (persistent_tunnels_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_lm
				:type (int)
				:val (10200)
			)
			: (peers_count_sz
				:type (int)
				:val (16384)
			)
			: (ipalloc_tab_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_tunnels_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_sessions_lm
				:type (int)
				:val (10000)
			)
			: (L2TP_lookup_lm
				:type (int)
				:val (10000)
			)
			: (max_concurrent_vpn_tunnels
				:type (int)
				:val (10000)
			)
			: (max_concurrent_gw_tunnels
				:type (int)
				:val (200)
			)
			: (fwsynatk_method
				:type (int)
				:val (0)
			)
			: (fwsynatk_timeout
				:type (int)
				:val (10)
			)
			: (fwsynatk_max
				:type (int)
				:val (5000)
			)
			: (fwsynatk_warning
				:type (int)
				:val (1)
			)
			: (fw_rst_expired_conn
				:type (bool)
				:val (false)
			)
			: (IPSec_cluster_nat
				:type (int)
				:val (0)
			)
			: (IPSec_main_if_nat
				:type (int)
				:val (0)
			)
			: (IPSec_orig_if_nat
				:type (int)
				:val (1)
			)
		)
		: (__global__
			: (conn_limit_notify_interval
				:type (int)
				:val (180)
			)
			: (conn_limit_reached_log
				:type (bool)
				:val (true)
			)
			: (tcptimeout
				:type (int)
				:val (3600)
			)
			: (tcpstarttimeout
				:type (int)
				:val (25)
			)
			: (tcpendtimeout
				:type (int)
				:val (20)
			)
			: (sip_early_nat
				:type (bool)
				:val (false)
			)
			: (using_account
				:type (bool)
				:val (false)
			)
			: (using_scv
				:type (bool)
				:val (true)
			)
			: (udpreply
				:type (bool)
				:val (true)
			)
			: (udpreply_from_any_port
				:type (bool)
				:val (true)
			)
			: (udptimeout
				:type (int)
				:val (40)
			)
			: (icmpreply
				:type (bool)
				:val (true)
			)
			: (icmperrors
				:type (bool)
				:val (true)
			)
			: (icmptimeout
				:type (int)
				:val (30)
			)
			: (otherreply
				:type (bool)
				:val (false)
			)
			: (othertimeout
				:type (int)
				:val (60)
			)
			: (dataconn_pendingtimeout
				:type (int)
				:val (60)
			)
			: (log_data_conns
				:type (bool)
				:val (false)
			)
			: (fw_tcp_seq_verify
				:type (bool)
				:val (false)
			)
			: (fw_trust_suspicious_rst
				:type (bool)
				:val (false)
			)
			: (fw_trust_suspicious_estab
				:type (bool)
				:val (false)
			)
			: (fw_tcp_seq_verify_log_level
				:type (int)
				:val (4)
			)
			: (fw_tcp_seq_verify_track_type
				:type (str)
				:val (log)
			)
			: (fw_virtual_defrag_log
				:type (str)
				:val (log)
			)
			: (addresstrans
				:type (bool)
				:val (true)
			)
			: (nat_automatic_rules_merge
				:type (bool)
				:val (true)
			)
			: (fwx_hide_extra_capacity
				:type (bool)
				:val (true)
			)
			: (hide_max_high_port
				:type (int)
				:val (60000)
			)
			: (hide_min_high_port
				:type (int)
				:val (10000)
			)
			: (hide_alloc_attempts
				:type (int)
				:val (50000)
			)
			: (fwx_ddcate_hide
				:type (int)
				:val (1)
			)
			: (fwx_ddcate_hide_non_crypt
				:type (int)
				:val (1)
			)
			: (stack_size
				:type (int)
				:val (0)
			)
			: (nrules
				:type (int)
				:val (144)
			)
			: (rulebase_uids_in_log
				:type (bool)
				:val (false)
			)
			: (disable_ipsec
				:type (bool)
				:val (false)
			)
			: (logical_servers_active
				:type (bool)
				:val (false)
			)
			: (tcpestb_grace_period
				:type (int)
				:val (0)
			)
			: (tcp_reject
				:type (bool)
				:val (true)
			)
			: (udp_reject
				:type (bool)
				:val (true)
			)
			: (ip_pool_log
				:type (int)
				:val (1)
			)
			: (maintenance_notification
				:type (str)
				:val (log)
			)
			: (fw_dns_verification
				:type (bool)
				:val (true)
			)
			: (fw_dns_xlation
				:type (bool)
				:val (false)
			)
			: (sam_track
				:type (str)
				:val (alert)
			)
			: (loggrace
				:type (int)
				:val (62)
			)
			: (ipoptslog
				:type (str)
				:val (none)
			)
			: (fw_allow_out_of_state_tcp
				:type (int)
				:val (1)
			)
			: (fw_allow_out_of_state_icmp
				:type (int)
				:val (1)
			)
			: (fw_log_out_of_state_tcp
				:type (int)
				:val (1)
			)
			: (fw_log_out_of_state_udp
				:type (int)
				:val (1)
			)
			: (fw_log_out_of_state_icmp
				:type (int)
				:val (1)
			)
			: (fw_log_out_of_state_other
				:type (int)
				:val (0)
			)
			: (unify_ctl_data_acct_logs
				:type (bool)
				:val (false)
			)
			: (validate_desktop_security
				:type (bool)
				:val (false)
			)
			: (allow_h323_t120
				:type (bool)
				:val (false)
			)
			: (allow_h323_through_ras
				:type (bool)
				:val (true)
			)
			: (h323_log_conn
				:type (bool)
				:val (true)
			)
			: (fwh323_allow_redirect
				:type (bool)
				:val (false)
			)
			: (h323_init_mem
				:type (bool)
				:val (true)
			)
			: (fwh323_force_src_phone
				:type (bool)
				:val (true)
			)
			: (allow_h323_h245_tunneling
				:type (bool)
				:val (false)
			)
			: (h323_enforce_setup
				:type (bool)
				:val (false)
			)
			: (sip_allow_redirect
				:type (bool)
				:val (true)
			)
			: (sip_enforce_security_reinvite
				:type (bool)
				:val (true)
			)
			: (sip_max_reinvite
				:type (int)
				:val (3)
			)
			: (net_quota_log
				:type (str)
				:val (alert)
			)
			: (net_quota_drop
				:type (int)
				:val (1)
			)
			: (net_quota_enabled
				:type (int)
				:val (0)
			)
			: (log_scv_drops
				:type (str)
				:val (log)
			)
			: (scv_gw_verify_only_mode
				:type (bool)
				:val (true)
			)
			: (enable_ip_options
				:type (int)
				:val (1)
			)
			: (generate_nat_log
				:type (int)
				:val (1)
			)
			: (use_VPN_communities
				:type (bool)
				:val (true)
			)
			: (voip_allow_no_from
				:type (bool)
				:val (false)
			)
			: (PDU_sequence
				:type (int)
				:val (16)
			)
			: (gtp_sequence_deviation_alert
				:type (int)
				:val (1)
			)
			: (gtp_sequence_deviation_drop
				:type (int)
				:val (0)
			)
			: (allow_PDU_sequence
				:type (int)
				:val (0)
			)
			: (check_flow_labels
				:type (int)
				:val (1)
			)
			: (gtp_anti_spoofing
				:type (int)
				:val (1)
			)
			: (gtp_allow_recreate_pdpc
				:type (str)
				:val (open)
			)
			: (gtp_track
				:type (str)
				:val (log)
			)
			: (gtp_max_req_retransmit
				:type (int)
				:val (5)
			)
			: (gtp_sam_close_upon_delete
				:type (bool)
				:val (false)
			)
			: (gtp_delete_upon_error
				:type (bool)
				:val (false)
			)
			: (gtp_allow_multi_if_ggsn
				:type (bool)
				:val (false)
			)
			: (gtp_chk_hdr_len
				:type (bool)
				:val (true)
			)
			: (gtp_echo_frequency
				:type (int)
				:val (60)
			)
			: (gtp_loggrace
				:type (int)
				:val (10)
			)
			: (gtp_echo_requires_path_in_use
				:type (bool)
				:val (false)
			)
			: (gtp_rate_limit_drop
				:type (bool)
				:val (true)
			)
			: (gtp_rate_limit_alert
				:type (bool)
				:val (true)
			)
			: (fw_clamp_tcp_mss
				:type (bool)
				:val (false)
			)
			: (cphwd_enable_templates
				:type (bool)
				:val (false)
			)
			: (cphwd_template_disable_rule
				:type (int)
				:val (1)
			)
			: (asm_max_ping_limit
				:type (bool)
				:val (true)
			)
			: (asm_max_ping_limit_size
				:type (int)
				:val (548)
			)
			: (asm_max_ping_limit_log
				:type (str)
				:val (log)
			)
			: (asm_ftp_bounce_log
				:type (str)
				:val (log)
			)
			: (asm_dns_verify_log
				:type (str)
				:val (log)
			)
			: (asm_land
				:type (bool)
				:val (true)
			)
			: (asm_land_log
				:type (str)
				:val (log)
			)
			: (asm_http_worm_catcher
				:type (bool)
				:val (true)
			)
			: (asm_http_worm_catcher_log
				:type (str)
				:val (alert)
			)
			: (asm_http_reverse_wc
				:type (bool)
				:val (false)
			)
			: (asm_http_worm1
				:type (str)
				:val ("MDAC overflow")
			)
			: (asm_http_worm1_pattern
				:type (str)
				:val ("msadcs\.dll")
			)
			: (asm_http_worm2
				:type (str)
				:val ("HTTP directory traversal attack")
			)
			: (asm_http_worm2_pattern
				:type (str)
				:val ("(\\|/)\.\.")
			)
			: (asm_http_worm3
				:type (str)
				:val ("Apache Tomcat RealPath")
			)
			: (asm_http_worm3_pattern
				:type (str)
				:val ("/test/realPath\.jsp")
			)
			: (asm_http_worm4
				:type (str)
				:val ("Apache Tomcat sample code")
			)
			: (asm_http_worm4_pattern
				:type (str)
				:val ("/test/jsp/buffer(1|2|3|4)\.jsp")
			)
			: (asm_http_worm5
				:type (str)
				:val ("Apache Tomcat path disclosure 1")
			)
			: (asm_http_worm5_pattern
				:type (str)
				:val ("/test/jsp/(comments|extends(1|2))\.jsp")
			)
			: (asm_http_worm6
				:type (str)
				:val ("Apache Tomcat path disclosure 2")
			)
			: (asm_http_worm6_pattern
				:type (str)
				:val ("/test/jsp/page(AutoFlush|Double|Extends|Import2|Info|Invalid|IsErrorPage|IsThreadSafe|Language|Session)\.jsp")
			)
			: (asm_http_worm7
				:type (str)
				:val ("Apache Tomcat path disclosure 3")
			)
			: (asm_http_worm7_pattern
				:type (str)
				:val ("/test/jsp/declaration/IntegerOverflow\.jsp")
			)
			: (asm_http_worm8
				:type (str)
				:val ("Apache Tomcat Malicious Request")
			)
			: (asm_http_worm8_pattern
				:type (str)
				:val ("/examples/jsp/source\.jsp\?(\?|/+.*/+)")
			)
			: (asm_http_worm9
				:type (str)
				:val ("BizTalk Buffer Overrun")
			)
			: (asm_http_worm9_pattern
				:type (str)
				:val ("biztalkhttpreceive\.dll\?")
			)
			: (asm_http_worm10
				:type (str)
				:val ("FrontPage Extensions Buffer Overrun")
			)
			: (asm_http_worm10_pattern
				:type (str)
				:val ("/_vti_bin/_vti_aut/fp30reg\.dll")
			)
			: (asm_http_worm11
				:type (str)
				:val ("Sanity.A Worm")
			)
			: (asm_http_worm11_pattern
				:type (str)
				:val ("/viewtopic\.php\?.*highlight='")
			)
			: (asm_http_worm12
				:type (str)
				:val ("Cisco IOS HTTP Server code injection vulnerability")
			)
			: (asm_http_worm12_pattern
				:type (str)
				:val ("(/level/15/exec/-/show/buffers)|(/level/15/exec/-/buffers/assigned/dump)")
			)
			: (asm_http_worm13
				:type (str)
				:val ("IIS Malformed URI DoS")
			)
			: (asm_http_worm13_pattern
				:type (str)
				:val ("/\.dll/.+[/\]~[0-9]")
			)
			: (asm_http_worm14
				:type (str)
				:val ("Macromedia JRun 4.0 View Source Vulnerabilities")
			)
			: (asm_http_worm14_pattern
				:type (str)
				:val ("\.cf([m]|([m][l])|[c])/[*]")
			)
			: (asm_http_worm15
				:type (str)
				:val ("PhpGedView Remote Execution Arbitrary Commands")
			)
			: (asm_http_worm15_pattern
				:type (str)
				:val ("help_text_vars\.php\?.+PGV_BASE_DIRECTORY\=(ftp|http|https)\:\/")
			)
			: (asm_http_worm16
				:type (str)
				:val ("Generic phpbb Remote Execution Arbitrary Commands")
			)
			: (asm_http_worm16_pattern
				:type (str)
				:val ("\.php\?.*phpbb_root_path=(ftp|http|https)\:\/")
			)
			: (asm_http_worm17
				:type (str)
				:val ("HP OpenView Remote Command Execution")
			)
			: (asm_http_worm17_pattern
				:type (str)
				:val ("connectedNodes\.ovpl\?node=.*[\|$;`]")
			)
			: (asm_http_worm18
				:type (str)
				:val ("PHP shell/web defacement tool ")
			)
			: (asm_http_worm18_pattern
				:type (str)
				:val ("\?ref=http\:\/\/.*\.dot\?&cmd=")
			)
			: (asm_http_worm19
				:type (str)
				:val ("PHP ADOdb Test Scripts")
			)
			: (asm_http_worm19_pattern
				:type (str)
				:val ("/tests/tmssql\.php\?do=")
			)
			: (asm_http_worm20
				:type (str)
				:val ("PHP Remote File Inclusion")
			)
			: (asm_http_worm20_pattern
				:type (str)
				:val ("\.php/.*\?.*globals")
			)
			: (asm_http_worm21
				:type (str)
				:val ("Oracle Reports File Overwrite")
			)
			: (asm_http_worm21_pattern
				:type (str)
				:val ("reports/rwservlet\?.*desformat=xml")
			)
			: (asm_http_worm22
				:type (str)
				:val ("Oracle Reports Directory Traversal(1)")
			)
			: (asm_http_worm22_pattern
				:type (str)
				:val ("reports/rwservlet\?.*(destype=file|desformat).*(destype=file|desformat)")
			)
			: (asm_http_worm23
				:type (str)
				:val ("Oracle Reports Directory Traversal(2)")
			)
			: (asm_http_worm23_pattern
				:type (str)
				:val ("reports/rwservlet\?.*(desformat=pdf|desname=).*(desformat=pdf|desname=)")
			)
			: (asm_http_worm24
				:type (str)
				:val ("ezDatabase Remote File Inclusion")
			)
			: (asm_http_worm24_pattern
				:type (str)
				:val ("visitorupload\.php.*\?.*db_id=.*\;")
			)
			: (asm_http_worm25
				:type (str)
				:val ("Cisco IOS CDP Status Page Code Injection")
			)
			: (asm_http_worm25_pattern
				:type (str)
				:val ("/level/15/exec/-/show/cdp/")
			)
			: (asm_http_worm26
				:type (str)
				:val ("SHOUTcast Filename Request Format String")
			)
			: (asm_http_worm26_pattern
				:type (str)
				:val ("/content/.*%.*.mp3")
			)
			: (asm_http_worm27
				:type (str)
				:val ("IBM Tivoli Access Manager Directory Traversal")
			)
			: (asm_http_worm27_pattern
				:type (str)
				:val ("pkmslogout\?.*filename=.*\.\.\/")
			)
			: (asm_http_worm28
				:type (str)
				:val ("Microsoft FrontPage XSS Vulnerability (MS06-017)")
			)
			: (asm_http_worm28_pattern
				:type (str)
				:val ("/_vti_bin/_vti_adm/fpadmdll\.dll")
			)
			: (asm_http_worm29
				:type (str)
				:val ("Adobe Reader Extensions Vulnerability 1")
			)
			: (asm_http_worm29_pattern
				:type (str)
				:val ("/ads\-readerext/ads\-readerext\?.*action(ID|id)=")
			)
			: (asm_http_worm30
				:type (str)
				:val ("Adobe Reader Extensions Vulnerability 2")
			)
			: (asm_http_worm30_pattern
				:type (str)
				:val ("/altercast/(A|a)lter(C|c)ast\?.*op=")
			)
			: (asm_http_worm31
				:type (str)
				:val ("osCommerce SQL Injection Vulnerability")
			)
			: (asm_http_worm31_pattern
				:type (str)
				:val ("/extras/update\.php\?.*readme_file=[^a-zA-Z0-9\-]")
			)
			: (asm_http_worm32
				:type (str)
				:val ("Ipswitch WhatsUp Professional XSS Vulnerability 1")
			)
			: (asm_http_worm32_pattern
				:type (str)
				:val ("/(N|n)m(C|c)onsole/(N|n)avigation\.asp\?.*(D|d)evice(V|v)iew")
			)
			: (asm_http_worm33
				:type (str)
				:val ("Ipswitch WhatsUp Professional XSS Vulnerability 2")
			)
			: (asm_http_worm33_pattern
				:type (str)
				:val ("/(N|n)m(C|c)onsole/(T|t)ool(R|r)esults\.asp\?.*s(H|h)ostname.*=.*script")
			)
			: (asm_http_worm34
				:type (str)
				:val ("Ipswitch WhatsUp Professional Source Disclosure")
			)
			: (asm_http_worm34_pattern
				:type (str)
				:val ("/(N|n)m(C|c)onsole/(L|l)ogin\.asp")
			)
			: (asm_http_worm35
				:type (str)
				:val ("Ipswitch WhatsUp RenderMap Vulnerability")
			)
			: (asm_http_worm35_pattern
				:type (str)
				:val ("/(N|n)m(C|c)onsole/utility/(R|r)ender(M|m)ap\.asp\?")
			)
			: (asm_http_worm36
				:type (str)
				:val ("Ipswitch WhatsUp HTTP Bypass Vulnerability")
			)
			: (asm_http_worm36_pattern
				:type (str)
				:val ("/(N|n)m(C|c)onsole/(D|d)efault\.asp\?.*(J|j)ava(S|s)cript(D|d)isabled")
			)
			: (asm_http_worm37
				:type (str)
				:val ("SAP Phishing Vulnerability")
			)
			: (asm_http_worm37_pattern
				:type (str)
				:val ("/(W|w)m(R|r)oot/adapter\-index\.dsp\?")
			)
			: (asm_http_worm38
				:type (str)
				:val ("SAP Business Connector Parameter Handling 1")
			)
			: (asm_http_worm38_pattern
				:type (str)
				:val ("/(SAP|sap)/chop(SAP|sap)(L|l)og\.dsp\?.*full(N|n)ame")
			)
			: (asm_http_worm39
				:type (str)
				:val ("SAP Business Connector Parameter Handling 2")
			)
			: (asm_http_worm39_pattern
				:type (str)
				:val ("/invoke/sap\.monitor\.rfc(T|t)race/delete(S|s)ingle")
			)
			: (asm_http_worm40
				:type (str)
				:val ("Symantec Sygate Management Server SQL Injection")
			)
			: (asm_http_worm40_pattern
				:type (str)
				:val ("/servlet/(S|s)ygate\.(S|s)ervlet\.login.*\?.*uid=.*test.*&up=.*test")
			)
			: (asm_http_worm41
				:type (str)
				:val ("Horde Help Viewer Vulnerability")
			)
			: (asm_http_worm41_pattern
				:type (str)
				:val ("services/help/index\.php.*module=horde")
			)
			: (asm_http_worm42
				:type (str)
				:val ("VWar Remote File Inclusion Vulnerability")
			)
			: (asm_http_worm42_pattern
				:type (str)
				:val ("vwar_root=.*(ftp|https?):/")
			)
			: (asm_http_worm43
				:type (str)
				:val ("AWStats Remote Command Execution Vulnerability")
			)
			: (asm_http_worm43_pattern
				:type (str)
				:val ("/awstats\.pl\?(configdir|update|pluginmode)=.*(\|.+\||system)")
			)
			: (asm_http_worm44
				:type (str)
				:val ("AWStats migrate Command Injection Vulnerability")
			)
			: (asm_http_worm44_pattern
				:type (str)
				:val ("/awstats\.pl\?.*migrate")
			)
			: (asm_http_worm45
				:type (str)
				:val ("Simplog Remote Commands Vulnerability")
			)
			: (asm_http_worm45_pattern
				:type (str)
				:val ("/doc/index\.php\?.*(cmd|.|:|\\|/|~)")
			)
			: (asm_http_worm46
				:type (str)
				:val ("IPSwitch WhatsUp Professional DoS")
			)
			: (asm_http_worm46_pattern
				:type (str)
				:val ("/nmconsole/login\.asp\?.*(\[|\])")
			)
			: (asm_http_worm47
				:type (str)
				:val ("Oracle Reports Arbitrary File Writing Vulnerability")
			)
			: (asm_http_worm47_pattern
				:type (str)
				:val ("/forms90/f90servlet\?(module|form)=([a-z]:|\/|.*\.\.)")
			)
			: (asm_http_worm48
				:type (str)
				:val ("Geeklog Remote Code Execution Vulnerability")
			)
			: (asm_http_worm48_pattern
				:type (str)
				:val ("(CONF|conf)\[.*\]=(http|ftp)://")
			)
			: (asm_http_worm49
				:type (str)
				:val ("qck.cc Spyware Installer")
			)
			: (asm_http_worm49_pattern
				:type (str)
				:val ("/x(/in\.php\?)|(/tbd_web\.php\?)wm=")
			)
			: (asm_http_worm50
				:type (str)
				:val ("WebAttacker Spyware")
			)
			: (asm_http_worm50_pattern
				:type (str)
				:val ("ie060(4|1)\.cgi\?(exploit|bug)")
			)
			: (asm_http_worm51
				:type (str)
				:val ("Cisco CallManager Phonelist XSS Vulnerability")
			)
			: (asm_http_worm51_pattern
				:type (str)
				:val ("/ccmadmin/phonelist\.asp\?")
			)
			: (asm_http_worm52
				:type (str)
				:val ("Cisco CallManager Logon XSS Vulnerability")
			)
			: (asm_http_worm52_pattern
				:type (str)
				:val ("/ccmuser/logon\.asp\?")
			)
			: (asm_http_worm53
				:type (str)
				:val ("Plume CMS manager_path Remote Code Execution")
			)
			: (asm_http_worm53_pattern
				:type (str)
				:val ("/manager/frontinc/prepend\.php")
			)
			: (asm_http_worm54
				:type (str)
				:val ("ASP.NET Information Disclosure Vulnerability (MS06-033)")
			)
			: (asm_http_worm54_pattern
				:type (str)
				:val ("(/app_.*(\\|%.*5c))|(/.*(\\|%.*5c).*app_)")
			)
			: (asm_http_worm55
				:type (str)
				:val ("phpSysInfo Vulnerability")
			)
			: (asm_http_worm55_pattern
				:type (str)
				:val ("%00")
			)
			: (asm_http_worm56
				:type (str)
				:val ("MiniBB Remote File Vulnerability 1")
			)
			: (asm_http_worm56_pattern
				:type (str)
				:val ("/components/com_minibb\.php.*\?.*http://")
			)
			: (asm_http_worm57
				:type (str)
				:val ("MiniBB Remote File Vulnerability 2")
			)
			: (asm_http_worm57_pattern
				:type (str)
				:val ("/components/minibb/index\.php.*\?.*http://")
			)
			: (asm_http_worm58
				:type (str)
				:val ("Apache LDAP HTTP Server Buffer Overflow Vulnerability")
			)
			: (asm_http_worm58_pattern
				:type (str)
				:val ("ldap://.*(/).*(\?).*(\?).*(\?).*(\?).*(\?)")
			)
			: (asm_http_worm59
				:type (str)
				:val ("Indexing Service XSS Vulnerability MS06-053")
			)
			: (asm_http_worm59_pattern
				:type (str)
				:val ("\+(A|a)(D|d)w-(SCRIPT|script)\+(A|a)(D|d)4-")
			)
			: (asm_http_worm60
				:type (str)
				:val ("CBSMS Mambo Module Remote File Vulnerability")
			)
			: (asm_http_worm60_pattern
				:type (str)
				:val ("mos(C|c)onfig_absolute_path=")
			)
			: (asm_http_worm61
				:type (str)
				:val ("C-News remote file inclusion vulnerability")
			)
			: (asm_http_worm61_pattern
				:type (str)
				:val ("/affichage/commentaires\.php\?path=http")
			)
			: (asm_http_worm62
				:type (str)
				:val ("phpFullAnnu remote file inclusion vulnerability")
			)
			: (asm_http_worm62_pattern
				:type (str)
				:val ("/modules/home\.module\.php\?repmod=")
			)
			: (asm_http_worm63
				:type (str)
				:val ("Beautifier remote file inclusion vulnerability")
			)
			: (asm_http_worm63_pattern
				:type (str)
				:val ("/(C|c)ore\.php\?(BEAUT_PATH|beaut_path)=")
			)
			: (asm_http_worm64
				:type (str)
				:val ("W-Agora multiple file inclusion vulnerabilitiy")
			)
			: (asm_http_worm64_pattern
				:type (str)
				:val ("\?(inc|cfg)_dir.*=(http|ftp)")
			)
			: (asm_http_worm65
				:type (str)
				:val ("MSN Messenger Live 8")
			)
			: (asm_http_worm65_pattern
				:type (str)
				:val ("/gateway/gateway\.dll")
			)
			: (asm_http_worm66
				:type (str)
				:val ("Acrobat Reader denial of service")
			)
			: (asm_http_worm66_pattern
				:type (str)
				:val (".*\.pdf#.*####")
			)
			: (asm_http_worm67
				:type (str)
				:val ("Acrobat Reader UXSS vulnerability")
			)
			: (asm_http_worm67_pattern
				:type (str)
				:val (".*\.pdf#.*((j|J)ava(s|S)cript|(r|R)es:)")
			)
			: (asm_http_worm68
				:type (str)
				:val ("Acrobat Reader UXSS remote code execution")
			)
			: (asm_http_worm68_pattern
				:type (str)
				:val (".*\.pdf#.*(d|D)ocument\.(w|W)rite")
			)
			: (asm_http_worm69
				:type (str)
				:val ("Acrobat Reader CSRF vulnerability ")
			)
			: (asm_http_worm69_pattern
				:type (str)
				:val (".*\.pdf#.*(FDF|fdf|XML|xml).*(ftp|https?)://.*\?")
			)
			: (asm_http_worm70
				:type (str)
				:val ("PHPEventMan Remote File Inclusion")
			)
			: (asm_http_worm70_pattern
				:type (str)
				:val ("(text\.ctrl\.php|common\.function\.php)\?level=.*(ftp|https?)")
			)
			: (asm_http_worm71
				:type (str)
				:val ("CreaDirectory SQL Injection Vulnerability")
			)
			: (asm_http_worm71_pattern
				:type (str)
				:val ("/error\.asp\?id=-1\+union.*,(user_name|ipassword)")
			)
			: (asm_http_worm72
				:type (str)
				:val ("MX Smartor Remote File Vulnerability")
			)
			: (asm_http_worm72_pattern
				:type (str)
				:val ("/admin/admin_album_otf\.php\?phpbb_root_path=.*\?")
			)
			: (asm_http_worm73
				:type (str)
				:val ("TrojanDownloader Small Dam")
			)
			: (asm_http_worm73_pattern
				:type (str)
				:val ("/cp/rule\.php\?(name|fstt|gcu)=")
			)
			: (asm_http_worm74
				:type (str)
				:val ("TrojanDownloader Agent JVH ")
			)
			: (asm_http_worm74_pattern
				:type (str)
				:val ("/cp/bin/lim")
			)
			: (asm_http_worm75
				:type (str)
				:val ("Blueskyltd Spyware")
			)
			: (asm_http_worm75_pattern
				:type (str)
				:val ("/cntr\.php\?(b|e|a)=")
			)
			: (asm_http_worm76
				:type (str)
				:val ("CasinoOnNet Spyware")
			)
			: (asm_http_worm76_pattern
				:type (str)
				:val ("/logs\.asp\?(MSGID|msgid)=100")
			)
			: (asm_http_worm77
				:type (str)
				:val ("General SQL Injection Attack")
			)
			: (asm_http_worm77_pattern
				:type (str)
				:val ("(union|UNION).*(select|SELECT).*null,null,null,null,null,null,null,null")
			)
			: (asm_http_worm78
				:type (str)
				:val ("WANewsletter Remote File Include Vulnerability")
			)
			: (asm_http_worm78_pattern
				:type (str)
				:val ("newsletter/newsletter\.php\?waroot=.*(www|http|ftp|\?)")
			)
			: (asm_http_worm79
				:type (str)
				:val ("Frequency Clock Remote File Include Vulnerabilities")
			)
			: (asm_http_worm79_pattern
				:type (str)
				:val ("conf\.php\?securelib=.*(www|http|ftp|\?)")
			)
			: (asm_http_worm80
				:type (str)
				:val ("PNFlashGames PostNuke SQL Injection Vulnerability")
			)
			: (asm_http_worm80_pattern
				:type (str)
				:val ("\.php\?module=pn(F|f)lash(G|g)ames&func=view&cid=.*union.*select")
			)
			: (asm_http_worm81
				:type (str)
				:val ("BurnCMS Remote File Include Vulnerabilities 1")
			)
			: (asm_http_worm81_pattern
				:type (str)
				:val ("/lib/(authuser|misc|connect)\.php\?root=.*(http|ftp|www)")
			)
			: (asm_http_worm82
				:type (str)
				:val ("EsForum SQL Injection (CVE-2007-2259)")
			)
			: (asm_http_worm82_pattern
				:type (str)
				:val ("forum\.php\?idsalon=.*(union|UNION).*(select|SELECT)")
			)
			: (asm_http_worm83
				:type (str)
				:val ("BurnCMS Remote File Include Vulnerabilities 2")
			)
			: (asm_http_worm83_pattern
				:type (str)
				:val ("/lib/(db/mysql\.class|db/postgres\.class)\.php\?root=.*(http|ftp|www)")
			)
			: (asm_http_worm84
				:type (str)
				:val (CodeRed)
			)
			: (asm_http_worm84_pattern
				:type (str)
				:val ("\.ida\?")
			)
			: (asm_http_worm85
				:type (str)
				:val (Nimda)
			)
			: (asm_http_worm85_pattern
				:type (str)
				:val ("(cmd\.exe)|(root\.exe)")
			)
			: (asm_http_worm86
				:type (str)
				:val ("htr overflow")
			)
			: (asm_http_worm86_pattern
				:type (str)
				:val ("\.htr")
			)
			: (asm_cifs_max_buffer
				:type (int)
				:val (4000)
			)
			: (asm_ping_of_death
				:type (bool)
				:val (true)
			)
			: (asm_ping_of_death_log
				:type (str)
				:val (log)
			)
			: (asm_packet_verify_log
				:type (str)
				:val (log)
			)
			: (asm_packet_verify_relaxed_udp
				:type (bool)
				:val (true)
			)
			: (asm_small_pmtu
				:type (bool)
				:val (false)
			)
			: (asm_small_pmtu_size
				:type (int)
				:val (350)
			)
			: (asm_small_pmtu_log
				:type (str)
				:val (log)
			)
			: (asm_teardrop
				:type (bool)
				:val (true)
			)
			: (asm_teardrop_log
				:type (str)
				:val (log)
			)
			: (asm_fp_inout
				:type (bool)
				:val (true)
			)
			: (asm_fp_vpn
				:type (int)
				:val (1)
			)
			: (asm_fp_ttl
				:type (bool)
				:val (false)
			)
			: (asm_fp_ttl_value
				:type (int)
				:val (128)
			)
			: (asm_fp_ttl_tracert
				:type (bool)
				:val (true)
			)
			: (asm_fp_ttl_threshold
				:type (int)
				:val (30)
			)
			: (asm_fp_ipid
				:type (bool)
				:val (false)
			)
			: (asm_fp_ipid_mode
				:type (int)
				:val (3)
			)
			: (asm_fp_isn
				:type (bool)
				:val (false)
			)
			: (asm_fp_isn_bits
				:type (int)
				:val (24)
			)
			: (check_low_ports
				:type (bool)
				:val (true)
			)
			: (sip_allow_two_media_conns
				:type (bool)
				:val (false)
			)
			: (sip_allow_instant_messaging
				:type (bool)
				:val (false)
			)
			: (sip_header_content_verifier
				:type (bool)
				:val (true)
			)
			: (sip_accept_unknown_messages
				:type (bool)
				:val (false)
			)
			: (http_check_request_validity
				:type (bool)
				:val (true)
			)
			: (http_max_header_length
				:type (int)
				:val (2100)
			)
			: (http_max_header_num
				:type (int)
				:val (500)
			)
			: (http_max_request_url_length
				:type (int)
				:val (2048)
			)
			: (IOS_DOS_HOP_COUNT
				:type (int)
				:val (4)
			)
			: (bgp_port_number
				:type (int)
				:val (179)
			)
			: (rip_port_number
				:type (int)
				:val (520)
			)
			: (DNS_RR_COUNT
				:type (int)
				:val (20)
			)
			: (DNS_AR_COUNT
				:type (int)
				:val (20)
			)
			: (DNS_ARR_COUNT
				:type (int)
				:val (20)
			)
			: (asm_cifs_long_pswd
				:type (int)
				:val (100)
			)
			: (imap_cmd_limit
				:type (int)
				:val (200)
			)
			: (imap_literal_limit
				:type (int)
				:val (200)
			)
			: (cifs_bf_count
				:type (int)
				:val (100)
			)
			: (cifs_bf_timeout
				:type (int)
				:val (60)
			)
			: (gpd_maxsize
				:type (int)
				:val (100)
			)
			: (ws_userenum_maxsize
				:type (int)
				:val (100)
			)
			: (asm_cifs_block_null_sessions
				:type (bool)
				:val (false)
			)
			: (asm_cifs_block_popups
				:type (bool)
				:val (false)
			)
			: (asm_cifs_inspect_ntlm_ess_msgs
				:type (bool)
				:val (false)
			)
			: (RPC
				:type (bool)
				:val (true)
			)
			: (asm_dynamic_prop_msrpc_tcp
				:type (bool)
				:val (false)
			)
			: (DCERPC_ALLOW_135
				:type (bool)
				:val (false)
			)
			: (DCERPC_DROP_NO_AUTH
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_welchia
				:type (bool)
				:val (false)
			)
			: (WELCHIA_MON_ONLY
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_ios_dos
				:type (bool)
				:val (false)
			)
			: (IOS_DOS_MON_ONLY
				:type (bool)
				:val (false)
			)
			: (IOS_DOS_SWIPE
				:type (bool)
				:val (true)
			)
			: (IOS_DOS_IP_MOB
				:type (bool)
				:val (true)
			)
			: (IOS_DOS_SUN_ND
				:type (bool)
				:val (true)
			)
			: (IOS_DOS_PIM
				:type (bool)
				:val (true)
			)
			: (asm_dynamic_prop_SQL_CMDS
				:type (bool)
				:val (false)
			)
			: (MSSQL_CMDS_MON_ONLY
				:type (bool)
				:val (false)
			)
			: (ENABLE_SLAMMER_PROT
				:type (bool)
				:val (true)
			)
			: (ENABLE_02_03_PROT
				:type (bool)
				:val (true)
			)
			: (ENABLE_08_PROT
				:type (bool)
				:val (true)
			)
			: (ENABLE_0A_PROT
				:type (bool)
				:val (true)
			)
			: (asm_dynamic_prop_msasn1
				:type (bool)
				:val (false)
			)
			: (MSASN1_MON_ONLY
				:type (bool)
				:val (false)
			)
			: (MSASN1_CIFS
				:type (bool)
				:val (true)
			)
			: (MSASN1_KRB
				:type (bool)
				:val (true)
			)
			: (MSASN1_LDAP
				:type (bool)
				:val (true)
			)
			: (MSASN1_DCERPC
				:type (bool)
				:val (true)
			)
			: (asm_dynamic_prop_msasn1_smtp
				:type (bool)
				:val (false)
			)
			: (MSASN1_SMTP_mon_only
				:type (bool)
				:val (false)
			)
			: (VPN
				:type (bool)
				:val (true)
			)
			: (asm_dynamic_prop_openssl
				:type (bool)
				:val (false)
			)
			: (SSL_mon_only
				:type (bool)
				:val (false)
			)
			: (OPENSSL_IMAPS
				:type (bool)
				:val (false)
			)
			: (OPENSSL_LDAPS
				:type (bool)
				:val (false)
			)
			: (OPENSSL_POP3S
				:type (bool)
				:val (false)
			)
			: (OPENSSL_SMTPS
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_ike_agr
				:type (bool)
				:val (false)
			)
			: (asm_ike_agr_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_ike_agr_check_nat_t
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_sasser
				:type (bool)
				:val (false)
			)
			: (asm_sasser_mon_only
				:type (bool)
				:val (false)
			)
			: (Routing
				:type (bool)
				:val (true)
			)
			: (asm_dynamic_prop_ospf
				:type (bool)
				:val (false)
			)
			: (ospf_mon_only
				:type (bool)
				:val (false)
			)
			: (ospf_auth_only
				:type (bool)
				:val (true)
			)
			: (bgp_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_bgp
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_rip
				:type (bool)
				:val (false)
			)
			: (rip_mon_only
				:type (bool)
				:val (false)
			)
			: (rip_ver2_only
				:type (bool)
				:val (true)
			)
			: (rip_md5_only
				:type (bool)
				:val (true)
			)
			: (Conntent_protection
				:type (bool)
				:val (true)
			)
			: (asm_dynamic_prop_dns_rr
				:type (bool)
				:val (false)
			)
			: (dns_rr_mon_only
				:type (bool)
				:val (true)
			)
			: (SUN_RPC
				:type (bool)
				:val (true)
			)
			: (rpclookup_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_rpclookup
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_wins_rep
				:type (bool)
				:val (false)
			)
			: (wins_rep_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_igmp_prot
				:type (bool)
				:val (false)
			)
			: (igmp_prot_mon_only
				:type (bool)
				:val (false)
			)
			: (igmp_prot_multi_only
				:type (bool)
				:val (true)
			)
			: (asm_dynamic_prop_nbns
				:type (bool)
				:val (false)
			)
			: (nbns_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_dhcp
				:type (bool)
				:val (false)
			)
			: (dhcp_mon_only
				:type (bool)
				:val (false)
			)
			: (dhcp_enforce_options
				:type (bool)
				:val (true)
			)
			: (dhcp_block_bootp
				:type (bool)
				:val (false)
			)
			: (dhcp_enforce_etherenet
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_ani
				:type (bool)
				:val (false)
			)
			: (ani_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_sd_http_enc
				:type (bool)
				:val (false)
			)
			: (http_enc_mon_only
				:type (bool)
				:val (false)
			)
			: (http_block_null
				:type (bool)
				:val (true)
			)
			: (asm_cifs_block_long_pswd
				:type (bool)
				:val (false)
			)
			: (asm_cifs_long_pswd_log_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_gif
				:type (bool)
				:val (false)
			)
			: (gif_mon_only
				:type (bool)
				:val (false)
			)
			: (GIF_SCAN_STRICT_DETECTION
				:type (bool)
				:val (true)
			)
			: (OSX_GIF
				:type (bool)
				:val (false)
			)
			: (JAVA_GIF
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_telnet_env_cmd
				:type (bool)
				:val (false)
			)
			: (TELNET_ENV_CMD_MON_ONLY
				:type (bool)
				:val (false)
			)
			: (veritas_protection
				:type (bool)
				:val (true)
			)
			: (asm_dynamic_prop_veritas_r_reg
				:type (bool)
				:val (false)
			)
			: (veritas_r_reg_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_veritas_dos
				:type (bool)
				:val (false)
			)
			: (veritas_dos_mon_only
				:type (bool)
				:val (false)
			)
			: (veritas_clnt_a
				:type (bool)
				:val (false)
			)
			: (veritas_clnt_pwd
				:type (bool)
				:val (false)
			)
			: (veritas_clnt_dos
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_win_smb_prot
				:type (bool)
				:val (false)
			)
			: (win_smb_prot_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_msmq_prot
				:type (bool)
				:val (false)
			)
			: (msmq_prot_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_rtf
				:type (bool)
				:val (false)
			)
			: (rtf_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_pdf
				:type (bool)
				:val (false)
			)
			: (pdf_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_solaris_telnet
				:type (bool)
				:val (false)
			)
			: (solaris_telnet_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_snmp_protector
				:type (bool)
				:val (true)
			)
			: (snmp_enf
				:type (bool)
				:val (false)
			)
			: (snmp_protector_mon_only
				:type (bool)
				:val (false)
			)
			: (snmp_ms_bulk
				:type (bool)
				:val (false)
			)
			: (snmp_ms_bulk_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_bpcd_connect
				:type (bool)
				:val (false)
			)
			: (bpcd_connect_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_bpcd_chain
				:type (bool)
				:val (false)
			)
			: (bpcd_chain_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_ca_discovery
				:type (bool)
				:val (false)
			)
			: (ca_discovery_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_tftp_long_fn
				:type (bool)
				:val (false)
			)
			: (tftp_long_fn_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_tivoli_iso
				:type (bool)
				:val (false)
			)
			: (tivoli_iso_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_novell_netmail
				:type (bool)
				:val (false)
			)
			: (novell_netmail_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_capicom_vul
				:type (bool)
				:val (false)
			)
			: (capicom_vul_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_win32_api
				:type (bool)
				:val (false)
			)
			: (win32_api_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_asf
				:type (bool)
				:val (false)
			)
			: (asf_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_wab
				:type (bool)
				:val (false)
			)
			: (block_wab_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_smb_trans
				:type (bool)
				:val (false)
			)
			: (smb_trans_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_smb_rename
				:type (bool)
				:val (false)
			)
			: (smb_rename_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_mailslot
				:type (bool)
				:val (false)
			)
			: (mailslot_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_office
				:type (bool)
				:val (false)
			)
			: (block_office_mon_only
				:type (bool)
				:val (false)
			)
			: (office_word_block
				:type (bool)
				:val (true)
			)
			: (office_excel_block
				:type (bool)
				:val (true)
			)
			: (office_ppt_block
				:type (bool)
				:val (true)
			)
			: (office_visio_block
				:type (bool)
				:val (false)
			)
			: (office_publis_block
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_excel_bof
				:type (bool)
				:val (false)
			)
			: (excel_bof_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_upnp_ms07_019
				:type (bool)
				:val (false)
			)
			: (upnp_ms07_019_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_ssh_kex
				:type (bool)
				:val (false)
			)
			: (ssh_kex_mon_only
				:type (bool)
				:val (false)
			)
			: (all_imap_long
				:type (bool)
				:val (false)
			)
			: (imap_long_mon_only
				:type (bool)
				:val (false)
			)
			: (imap_fetch
				:type (bool)
				:val (false)
			)
			: (imap_fetch_mon_only
				:type (bool)
				:val (false)
			)
			: (imap_examine
				:type (bool)
				:val (false)
			)
			: (imap_examine_mon_only
				:type (bool)
				:val (false)
			)
			: (imap_appnd
				:type (bool)
				:val (false)
			)
			: (imap_appnd_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_imap
				:type (bool)
				:val (true)
			)
			: (imap_list
				:type (bool)
				:val (false)
			)
			: (imap_list_mon_only
				:type (bool)
				:val (false)
			)
			: (imap_login
				:type (bool)
				:val (false)
			)
			: (imap_login_mon_only
				:type (bool)
				:val (false)
			)
			: (imap_select
				:type (bool)
				:val (false)
			)
			: (imap_select_mon_only
				:type (bool)
				:val (false)
			)
			: (imap_literal
				:type (bool)
				:val (false)
			)
			: (imap_literal_mon_only
				:type (bool)
				:val (false)
			)
			: (imap_buf
				:type (bool)
				:val (false)
			)
			: (imap_buf_mon_only
				:type (bool)
				:val (false)
			)
			: (imap_dir_trav
				:type (bool)
				:val (false)
			)
			: (imap_dir_trav_mon_only
				:type (bool)
				:val (false)
			)
			: (imap_cram_md5
				:type (bool)
				:val (false)
			)
			: (imap_cram_md5_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_novell_nmap
				:type (bool)
				:val (false)
			)
			: (novell_nmap_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_LDAP
				:type (bool)
				:val (false)
			)
			: (ldap_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_nfs
				:type (bool)
				:val (false)
			)
			: (nfs_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_wmp
				:type (bool)
				:val (false)
			)
			: (wmp_mon_only
				:type (bool)
				:val (false)
			)
			: (bmp_suspect_all
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_eot
				:type (bool)
				:val (false)
			)
			: (eot_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_cifs_bf
				:type (bool)
				:val (false)
			)
			: (cifs_bf_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_SQL_CMDS_T
				:type (bool)
				:val (false)
			)
			: (MSSQL_CMDS_T_MON_ONLY
				:type (bool)
				:val (false)
			)
			: (ENABLE_SA_BLANK_PASS
				:type (bool)
				:val (true)
			)
			: (ENABLE_XP_PROT
				:type (bool)
				:val (true)
			)
			: (ENABLE_SP_PROT
				:type (bool)
				:val (true)
			)
			: (ENFORCE_SQL_WINLOGIN
				:type (bool)
				:val (false)
			)
			: (MSSQL_CMDS_T_PRELOGIN
				:type (bool)
				:val (false)
			)
			: (SQL_2433
				:type (bool)
				:val (false)
			)
			: (ALLOW_TDS_6
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_landesk
				:type (bool)
				:val (false)
			)
			: (block_landesk_mon_only
				:type (bool)
				:val (false)
			)
			: (web_clients_protections
				:type (bool)
				:val (true)
			)
			: (asm_dynamic_prop_MSIE_protect
				:type (bool)
				:val (false)
			)
			: (MSIE_PROTECTIONS_mon_only
				:type (bool)
				:val (false)
			)
			: (MSIE_PROTECTIONS_BLOCK_JAVAPRXY
				:type (bool)
				:val (false)
			)
			: (MSIE_BLOCK_COM_MS06042
				:type (bool)
				:val (false)
			)
			: (MSIE_BLOCK_CSS
				:type (bool)
				:val (false)
			)
			: (MSIE_BLOCK_MHTML2
				:type (bool)
				:val (false)
			)
			: (MSIE_BLOCK_MMC
				:type (bool)
				:val (false)
			)
			: (MSIE_BLOCK_WEBDAV
				:type (bool)
				:val (false)
			)
			: (MSIE_BLOCK_HEAP
				:type (bool)
				:val (false)
			)
			: (MSIE_PROTECTIONS_BLOCK_MS05_038
				:type (bool)
				:val (false)
			)
			: (MSIE_PROTECTIONS_BLOCK_MSDDS
				:type (bool)
				:val (false)
			)
			: (MSIE_PROTECTIONS_BLOCK_MS05_052
				:type (bool)
				:val (false)
			)
			: (MSIE_PROTECTIONS_BLOCK_WINDW
				:type (bool)
				:val (false)
			)
			: (MSIE_BLOCK_MS05_054
				:type (bool)
				:val (false)
			)
			: (MSIE_BLOCK_ISCOMPONENT
				:type (bool)
				:val (false)
			)
			: (MSIE_BLOCK_CREATETEXTRANGE
				:type (bool)
				:val (false)
			)
			: (MSIE_BLOCK_RDS_MDAC
				:type (bool)
				:val (false)
			)
			: (MSIE_BLOCK_MHTML_REDIRECT
				:type (bool)
				:val (false)
			)
			: (MSIE_BLOCK_COM_MS06013
				:type (bool)
				:val (false)
			)
			: (MSIE_BLOCK_COM_MS06021
				:type (bool)
				:val (false)
			)
			: (MSIE_BLOCK_ACTIVEX
				:type (bool)
				:val (false)
			)
			: (MSIE_BLOCK_HHCTRL
				:type (bool)
				:val (false)
			)
			: (BLOCK_UTF8
				:type (bool)
				:val (false)
			)
			: (MSIE_AJAX_COLLECTGARBAGE
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_heap_spray
				:type (bool)
				:val (false)
			)
			: (heap_spray_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_setslice
				:type (bool)
				:val (false)
			)
			: (block_setslice_mon_only
				:type (bool)
				:val (false)
			)
			: (web_clients_protections1
				:type (bool)
				:val (true)
			)
			: (asm_dynamic_prop_block_vml
				:type (bool)
				:val (false)
			)
			: (block_vml_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_agent
				:type (bool)
				:val (false)
			)
			: (block_agent_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_xml
				:type (bool)
				:val (false)
			)
			: (block_xml_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_wmi
				:type (bool)
				:val (false)
			)
			: (block_wmi_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_script
				:type (bool)
				:val (false)
			)
			: (block_script_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_vml_block2
				:type (bool)
				:val (false)
			)
			: (vml_block2_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_adodb
				:type (bool)
				:val (false)
			)
			: (block_adodb_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_imsdll
				:type (bool)
				:val (false)
			)
			: (block_imsdll_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_hhocx
				:type (bool)
				:val (false)
			)
			: (block_hhocx_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_aol
				:type (bool)
				:val (false)
			)
			: (block_aol_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_citirx
				:type (bool)
				:val (false)
			)
			: (block_citirx_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_trend
				:type (bool)
				:val (false)
			)
			: (block_trend_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_oradc
				:type (bool)
				:val (false)
			)
			: (block_oradc_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_syman
				:type (bool)
				:val (false)
			)
			: (block_syman_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_block_mc
				:type (bool)
				:val (false)
			)
			: (block_mc_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_ms_07027
				:type (bool)
				:val (false)
			)
			: (ms_07027_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_css_tag
				:type (bool)
				:val (false)
			)
			: (css_tag_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_ms_0733
				:type (bool)
				:val (false)
			)
			: (ms_0733_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_mso_data
				:type (bool)
				:val (false)
			)
			: (mso_data_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_msrpc_ovr_cifs
				:type (bool)
				:val (false)
			)
			: (MSRPC_OVER_CIFS_MON_ONLY
				:type (bool)
				:val (false)
			)
			: (MSRPC_OVER_CIFS_BLOCK_MS05_039
				:type (bool)
				:val (true)
			)
			: (asm_dynamic_prop_jpeg
				:type (bool)
				:val (false)
			)
			: (jpeg_mon_only
				:type (bool)
				:val (false)
			)
			: (JPEG_SCAN_STRICT_DETECTION
				:type (bool)
				:val (true)
			)
			: (ENCODED_JPEG
				:type (bool)
				:val (false)
			)
			: (JPEG_ICC
				:type (bool)
				:val (false)
			)
			: (JPEG_REN
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_tiff
				:type (bool)
				:val (false)
			)
			: (tiff_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_avi
				:type (bool)
				:val (false)
			)
			: (avi_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_asx
				:type (bool)
				:val (false)
			)
			: (asx_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_mit_kerb_admin
				:type (bool)
				:val (false)
			)
			: (mit_kerb_admin_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_mit_kerb_unix
				:type (bool)
				:val (false)
			)
			: (mit_kerber_unix_auth_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_ldap_f_dos
				:type (bool)
				:val (false)
			)
			: (ldap_f_dos_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_ldap_mod_req
				:type (bool)
				:val (false)
			)
			: (ldap_mod_req_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_png
				:type (bool)
				:val (false)
			)
			: (png_mon_only
				:type (bool)
				:val (false)
			)
			: (ASM_DCERPC_mon_only
				:type (bool)
				:val (false)
			)
			: (DCERPC_frags
				:type (bool)
				:val (true)
			)
			: (DCERPC_multi_context
				:type (bool)
				:val (true)
			)
			: (msrpc_MS05_047
				:type (bool)
				:val (false)
			)
			: (MSRPC_MS05_047_mon_only
				:type (bool)
				:val (false)
			)
			: (msrpc_MS05_051
				:type (bool)
				:val (false)
			)
			: (MSRPC_MS05_051_mon_only
				:type (bool)
				:val (false)
			)
			: (msrpc_MS05_046
				:type (bool)
				:val (false)
			)
			: (MSRPC_MS05_046_mon_only
				:type (bool)
				:val (false)
			)
			: (msrpc_MS05_043
				:type (bool)
				:val (false)
			)
			: (MSRPC_MS05_043_mon_only
				:type (bool)
				:val (false)
			)
			: (msrpc_WEBDAV
				:type (bool)
				:val (false)
			)
			: (MSRPC_WEBDAV_mon_only
				:type (bool)
				:val (false)
			)
			: (msrpc_sasser
				:type (bool)
				:val (false)
			)
			: (MSRPC_SASSER_mon_only
				:type (bool)
				:val (false)
			)
			: (ms06_040
				:type (bool)
				:val (false)
			)
			: (ms06_040_mon_only
				:type (bool)
				:val (false)
			)
			: (rasman
				:type (bool)
				:val (false)
			)
			: (rasman_mon_only
				:type (bool)
				:val (false)
			)
			: (ms06_070
				:type (bool)
				:val (false)
			)
			: (ms06_070_mon_only
				:type (bool)
				:val (false)
			)
			: (netware
				:type (bool)
				:val (false)
			)
			: (netware_mon_only
				:type (bool)
				:val (false)
			)
			: (nwspool
				:type (bool)
				:val (false)
			)
			: (nwspool_mon_only
				:type (bool)
				:val (false)
			)
			: (spoolss_gpd
				:type (bool)
				:val (false)
			)
			: (spoolss_gpd_mon_only
				:type (bool)
				:val (false)
			)
			: (gpd_cumul
				:type (bool)
				:val (false)
			)
			: (msrpc_dns
				:type (bool)
				:val (false)
			)
			: (msrpc_dns_mon_only
				:type (bool)
				:val (false)
			)
			: (msrpc_dfs
				:type (bool)
				:val (false)
			)
			: (msrpc_dfs_mon_only
				:type (bool)
				:val (false)
			)
			: (ws_userenum
				:type (bool)
				:val (false)
			)
			: (ws_userenum_mon_only
				:type (bool)
				:val (false)
			)
			: (ws_userenum_cumulative
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_wmf_emf
				:type (bool)
				:val (false)
			)
			: (WMF_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_art
				:type (bool)
				:val (false)
			)
			: (art_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_dns_atma
				:type (bool)
				:val (false)
			)
			: (dns_atma_mon_only
				:type (bool)
				:val (true)
			)
			: (asm_dynamic_prop_cbo
				:type (bool)
				:val (false)
			)
			: (cbo_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_trend_micro
				:type (bool)
				:val (false)
			)
			: (trend_micro_mon_only
				:type (bool)
				:val (false)
			)
			: (asm_dynamic_prop_quick_time_mp4
				:type (bool)
				:val (false)
			)
			: (quick_time_mp4_mon_only
				:type (bool)
				:val (false)
			)
			: (WELCHIA_LOG
				:type (str)
				:val (1)
			)
			: (IOS_DOS_LOG
				:type (str)
				:val (1)
			)
			: (ENABLE_MSSQL_LOG
				:type (str)
				:val (1)
			)
			: (MSASN1_LOG
				:type (str)
				:val (1)
			)
			: (MSASN1_SMTP_LOG
				:type (str)
				:val (1)
			)
			: (SSL_LOG
				:type (str)
				:val (1)
			)
			: (asm_ike_agr_log
				:type (str)
				:val (1)
			)
			: (asm_sasser_log
				:type (str)
				:val (1)
			)
			: (ospf_log
				:type (str)
				:val (1)
			)
			: (bgp_log
				:type (str)
				:val (1)
			)
			: (rip_log
				:type (str)
				:val (1)
			)
			: (ENABLE_DNS_RR_LOG
				:type (str)
				:val (1)
			)
			: (rpclookup_log
				:type (str)
				:val (1)
			)
			: (wins_rep_log
				:type (str)
				:val (1)
			)
			: (igmp_log_r55
				:type (str)
				:val (1)
			)
			: (nbns_report_r55
				:type (str)
				:val (1)
			)
			: (dhcp_report_r55
				:type (str)
				:val (1)
			)
			: (ani_report_r55
				:type (str)
				:val (1)
			)
			: (http_enc_log
				:type (str)
				:val (1)
			)
			: (ENABLE_GIF_LOG
				:type (str)
				:val (1)
			)
			: (TELNET_ENV_CMD_LOG_R55
				:type (str)
				:val (1)
			)
			: (VERITAS_R_REG_REPORT_R55
				:type (str)
				:val (1)
			)
			: (VERITAS_DOS_REPORT_R55
				:type (str)
				:val (1)
			)
			: (WIN_SMB_REPORT_R55
				:type (str)
				:val (1)
			)
			: (MSMQ_REPORT_R55
				:type (str)
				:val (1)
			)
			: (rtf_report_r55
				:type (str)
				:val (1)
			)
			: (pdf_report_r55
				:type (str)
				:val (1)
			)
			: (solaris_telnet_report_r55
				:type (str)
				:val (1)
			)
			: (snmp_protector_report_r55
				:type (str)
				:val (1)
			)
			: (snmp_ms_bulk_report_r55
				:type (str)
				:val (1)
			)
			: (bpcd_connect_report_r55
				:type (str)
				:val (1)
			)
			: (bpcd_chain_report_r55
				:type (str)
				:val (1)
			)
			: (ca_discovery_report_r55
				:type (str)
				:val (1)
			)
			: (tftp_long_fn_report_r55
				:type (str)
				:val (1)
			)
			: (tivoli_iso_report_r55
				:type (str)
				:val (1)
			)
			: (novell_netmail_report_r55
				:type (str)
				:val (1)
			)
			: (capicom_vul_report_r55
				:type (str)
				:val (1)
			)
			: (win32_api_report_r55
				:type (str)
				:val (1)
			)
			: (asf_report_r55
				:type (str)
				:val (1)
			)
			: (block_wab_report_r55
				:type (str)
				:val (1)
			)
			: (smb_trans_report_r55
				:type (str)
				:val (1)
			)
			: (smb_rename_report_r55
				:type (str)
				:val (1)
			)
			: (mailslot_report_r55
				:type (str)
				:val (1)
			)
			: (block_office_report_r55
				:type (str)
				:val (1)
			)
			: (excel_bof_report_r55
				:type (str)
				:val (1)
			)
			: (upnp_ms07_019_report_r55
				:type (str)
				:val (1)
			)
			: (ssh_kex_report_r55
				:type (str)
				:val (1)
			)
			: (imap_long_report_r55
				:type (str)
				:val (1)
			)
			: (imap_fetch_report_r55
				:type (str)
				:val (1)
			)
			: (imap_examine_report_r55
				:type (str)
				:val (1)
			)
			: (imap_appnd_report_r55
				:type (str)
				:val (1)
			)
			: (imap_list_report_r55
				:type (str)
				:val (1)
			)
			: (imap_login_report_r55
				:type (str)
				:val (1)
			)
			: (imap_select_report_r55
				:type (str)
				:val (1)
			)
			: (imap_literal_report_r55
				:type (str)
				:val (1)
			)
			: (imap_buf_report_r55
				:type (str)
				:val (1)
			)
			: (imap_dir_trav_report_r55
				:type (str)
				:val (1)
			)
			: (imap_cram_md5_report_r55
				:type (str)
				:val (1)
			)
			: (novell_nmap_report_r55
				:type (str)
				:val (1)
			)
			: (ldap_report_r55
				:type (str)
				:val (1)
			)
			: (nfs_report_r55
				:type (str)
				:val (1)
			)
			: (wmp_report_r55
				:type (str)
				:val (1)
			)
			: (eot_report_r55
				:type (str)
				:val (1)
			)
			: (cifs_bf_report_r55
				:type (str)
				:val (1)
			)
			: (block_landesk_report_r55
				:type (str)
				:val (1)
			)
			: (MSIE_PROTECTIONS_REPORT_R55
				:type (str)
				:val (1)
			)
			: (heap_spray_report_r55
				:type (str)
				:val (1)
			)
			: (block_setslice_report_r55
				:type (str)
				:val (1)
			)
			: (block_vml_report_r55
				:type (str)
				:val (1)
			)
			: (block_agent_report_r55
				:type (str)
				:val (1)
			)
			: (block_xml_report_r55
				:type (str)
				:val (1)
			)
			: (block_wmi_report_r55
				:type (str)
				:val (1)
			)
			: (block_script_report_r55
				:type (str)
				:val (1)
			)
			: (vml_block2_report_r55
				:type (str)
				:val (1)
			)
			: (block_adodb_report_r55
				:type (str)
				:val (1)
			)
			: (block_imsdll_report_r55
				:type (str)
				:val (1)
			)
			: (block_hhocx_report_r55
				:type (str)
				:val (1)
			)
			: (block_aol_report_r55
				:type (str)
				:val (1)
			)
			: (block_citirx_report_r55
				:type (str)
				:val (1)
			)
			: (block_trend_report_r55
				:type (str)
				:val (1)
			)
			: (block_oradc_report_r55
				:type (str)
				:val (1)
			)
			: (block_syman_report_r55
				:type (str)
				:val (1)
			)
			: (block_mc_report_r55
				:type (str)
				:val (1)
			)
			: (ms_07027_report_r55
				:type (str)
				:val (1)
			)
			: (css_tag_report_r55
				:type (str)
				:val (1)
			)
			: (ms_0733_report_r55
				:type (str)
				:val (1)
			)
			: (mso_data_report_r55
				:type (str)
				:val (1)
			)
			: (MSRPC_OVER_CIFS_REPORT_R55
				:type (str)
				:val (1)
			)
			: (ENABLE_JPEG_LOG
				:type (str)
				:val (1)
			)
			: (tiff_report_r55
				:type (str)
				:val (1)
			)
			: (avi_report_r55
				:type (str)
				:val (1)
			)
			: (asx_report_r55
				:type (str)
				:val (1)
			)
			: (mit_kerb_admin_report_r55
				:type (str)
				:val (1)
			)
			: (mit_kerber_unix_auth_report_r55
				:type (str)
				:val (1)
			)
			: (ldap_f_dos_report_r55
				:type (str)
				:val (1)
			)
			: (ldap_mod_req_report_r55
				:type (str)
				:val (1)
			)
			: (png_report_r55
				:type (str)
				:val (1)
			)
			: (MSRPC_PROT_PROPS_LOG_R55
				:type (str)
				:val (1)
			)
			: (log_msrpc_MS05_047_R55
				:type (str)
				:val (1)
			)
			: (log_msrpc_MS05_051_R55
				:type (str)
				:val (1)
			)
			: (log_msrpc_MS05_046_R55
				:type (str)
				:val (1)
			)
			: (log_msrpc_MS05_043_R55
				:type (str)
				:val (1)
			)
			: (log_msrpc_WEBDAV_R55
				:type (str)
				:val (1)
			)
			: (BLOCK_SASSER_LOG_R55
				:type (str)
				:val (1)
			)
			: (ms06_040_report_r55
				:type (str)
				:val (1)
			)
			: (rasman_report_r55
				:type (str)
				:val (1)
			)
			: (ms06_070_report_r55
				:type (str)
				:val (1)
			)
			: (netware_report_r55
				:type (str)
				:val (1)
			)
			: (nwspool_report_r55
				:type (str)
				:val (1)
			)
			: (spoolss_gpd_report_r55
				:type (str)
				:val (1)
			)
			: (msrpc_dns_report_r55
				:type (str)
				:val (1)
			)
			: (msrpc_dfs_report_r55
				:type (str)
				:val (1)
			)
			: (ws_userenum_report_r55
				:type (str)
				:val (1)
			)
			: (WMF_EMF_report_r55
				:type (str)
				:val (1)
			)
			: (art_report_r55
				:type (str)
				:val (1)
			)
			: (dns_atma_report_r55
				:type (str)
				:val (1)
			)
			: (cbo_report_r55
				:type (str)
				:val (1)
			)
			: (trend_micro_report_r55
				:type (str)
				:val (1)
			)
			: (quick_time_mp4_report_r55
				:type (str)
				:val (1)
			)
			: (asm_cifs_log_null_sessions
				:type (str)
				:val (log)
			)
			: (asm_cifs_log_popups
				:type (str)
				:val (alert)
			)
			: (asm_cifs_log_long_pswd
				:type (str)
				:val (log)
			)
			: (icmpcryptver
				:type (int)
				:val (1)
			)
			: (fwz_encap_mtu
				:type (int)
				:val (1)
			)
			: (vpn_conf_n_key_exch_prob
				:type (str)
				:val (log)
			)
			: (vpn_packet_handle_prob
				:type (str)
				:val (log)
			)
			: (vpn_success_key_exch
				:type (str)
				:val (log)
			)
			: (acceptdecrypt
				:type (int)
				:val (1)
			)
			: (sr_same_ip_log
				:type (int)
				:val (1)
			)
			: (sr_same_ip_block
				:type (int)
				:val (0)
			)
			: (enable_remote_user_connect_logs
				:type (int)
				:val (1)
			)
			: (sync_outbound_sa_pkt_count
				:type (int)
				:val (200000)
			)
			: (community_based_policy
				:type (int)
				:val (1)
			)
			: (fwsynatk_method
				:type (int)
				:val (0)
			)
			: (fwsynatk_timeout
				:type (int)
				:val (5)
			)
			: (fwsynatk_max
				:type (int)
				:val (5000)
			)
			: (fwsynatk_warning
				:type (int)
				:val (1)
			)
			: (nat_limit
				:type (int)
				:val (0)
			)
			: (nat_hashsize
				:type (int)
				:val (0)
			)
			: (fwfrag_limit
				:type (int)
				:val (200)
			)
			: (fwfrag_timeout
				:type (int)
				:val (1)
			)
			: (fwfrag_minsize
				:type (int)
				:val (0)
			)
			: (fwfrag_allow
				:type (bool)
				:val (true)
			)
			: (IPSec_cluster_nat
				:type (int)
				:val (0)
			)
			: (IPSec_main_if_nat
				:type (int)
				:val (0)
			)
			: (IPSec_orig_if_nat
				:type (int)
				:val (0)
			)
			: (n_apns
				:type (int)
				:val (0)
			)
		)
	)
)
