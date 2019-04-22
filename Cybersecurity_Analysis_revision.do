
/***********************************************************************************
File        : Cybersecurity_Anaysis_revision.do
Authors     : Ariel Dora Stern
Created     : 28 SEP 2017
Modified    : 29 JAN 2019
Description : Revision - BMJ Open
***********************************************************************************/

clear 
clear matrix
set mem 500m
set linesize 200
set more off
capture log close

cd "/Users/astern/Dropbox/Gordon_Landman_Kramer_Stern/D_Data"
use "simplified_mts.dta", clear
keep if yrdec>=2002
set more off
sum yrdec if pma==1
sum yrdec if pma==0

***
local classes = "CH CV DE GU HO OR RA SU"
foreach c in `classes'{
gen `c' = class == "`c'"
}

replace class="Clinical Chemistry" if class=="CH"
replace class="Cardiovascular" if class=="CV" 
replace class="Dental" if class=="DE" 
replace class="Gastroenterology, Urology" if class=="GU"
replace class="General Hospital" if class=="HO" 
replace class="Orthopedic" if class=="OR" 
replace class="Radiology" if class=="RA"
replace class="General, Plastic Surgery" if class=="SU" 
tab class

***

sum soft_dum_key soft_dum_mti
gen soft_dum_both = soft_dum_key == 1 & soft_dum_mti==1
sum soft_dum*
sum yrdec if soft_dum_mti == 1
sum yrdec if soft_dum_mti == 1 & pma== 1
sum yrdec if soft_dum_mti == 1 & pma== 0
*keep if soft_dum_both == 1 /*for now*/

*Do summaries flagged by MTI but not keywords use "software" more intensively? Not really, actually...
	*sum software if soft_dum_mti == 0 & soft_dum_key == 1
	*sum software if soft_dum_mti == 1

*list idnum if soft_dum_mti == 0 & soft_dum_key == 1 & software == 1 in 30000/35000

drop PostmarketManagementofCyber ProtectedCriticalInfrastructure     /*these are all zeros*/ 
drop hacker /*these are all ones???*/
local cybersecurity_list = "accesscontrol activeattack airgap antispywaresoftware antivirussoftware asymmetriccryptography cipher computernetworkdefense computersecurityincident cryptanalysis cryptographicalgorithm cryptography cyberecosystem cyberexercise cyberincident cyberinfrastructure cybersecurity cybersecurityroutine cybersecuritysignal databreach dataleakage datatheft decrypt  denialofservice designedinsecurity digitalforensics distributeddenialofservice dynamicattacksurface encrypt enterpriseriskmanagement exploit exploitationanalysis identityandaccessmanagement informationsecuritypolicy InformationSharingAnalysis informationsystemresilience InformationSystemsSecurity intrusiondetection maliciouscode malware NICCS NIST NISTFramework penetrationtesting phishing securityincident securitypolicy spyware symmetriccryptography symmetricencryptionalgorithm symmetrickey systemssecurityarchitecture threatassessment"

gen cybersec_dum = 0
foreach z in `cybersecurity_list'{
	gen `z'_dum=(`z'>0 & `z'!=.)
	label var `z'_dum "Flags if keyword `z' used at least once"
	replace cybersec_dum = 1 if `z' > 0  & `z'!=.
}
gen cybersec_dum_key = cybersec_dum == 1 & soft_dum_key == 1
gen cybersec_dum_mti = cybersec_dum == 1 & soft_dum_mti == 1


*added January 2019 in response to reviewer request:
preserve
keep *_dum
foreach z in `cybersecurity_list'{
	rename `z'_dum `z'
}
collapse (sum) `cybersecurity_list' 
export excel using keyword_frequencies, replace firstrow(variables)
restore


**********

*added on Oct 24 to pull random sample for hand-checking
set seed 61749
preserve
gen u1 = runiform()
sort u1
keep if cybersec_dum_mti == 1
keep if _n >50 & _n<=100
keep idnumber applicant_orig `cybersecurity_list'
export excel using sample4, replace  firstrow(variables)
restore

preserve
gen u1 = runiform()
sort u1
keep if cybersec_dum_mti == 0 & soft_dum_key ==1
keep if _n <=25
keep idnumber applicant_orig `cybersecurity_list'
export excel using sample2, replace firstrow(variables)
restore


**********************

sum yrdec if cybersec_dum_key == 1
sum yrdec if cybersec_dum_mti == 1

sort idnum yrdec
gen counter = 1
gen pma_soft = 1 if pma_flag == 1 & soft_dum_mti==1
gen k510_soft = 1 if pma_flag ==0 & soft_dum_mti==1

preserve
ttest soft_dum_mti, by(pma_flag) unequal
restore

preserve
keep if soft_dum_mti==1
ttest cybersec_dum_mti, by(pma_flag) unequal
restore

sum yrdec if cybersec_dum_mti == 1 & pma_soft ==1
sum yrdec if cybersec_dum_mti == 1 & k510_soft ==1

local acs = "CH CV DE GU HO OR RA SU"
local defs = "key mti"
foreach x in `acs' {
	foreach y in `defs' {
		gen `x'_s_`y' = soft_dum_`y'==1 & `x' == 1
		gen `x'_sc_`y' = `x'_s_`y' ==1 & cybersec_dum_`y' == 1
	}
}

*keep if soft_dum_both==1

collapse (sum) 	counter soft_dum_mti soft_dum_key cybersec_dum_mti cybersec_dum_key ///
		 CH CV DE GU HO OR RA SU ///
		 CH_s_m CV_s_m DE_s_m GU_s_m HO_s_m OR_s_m RA_s_m SU_s_m ///
		 CH_sc_m CV_sc_m DE_sc_m GU_sc_m HO_sc_m OR_sc_m RA_sc_m SU_sc_m ///		
		 CH_s_k CV_s_k DE_s_k GU_s_k HO_s_k OR_s_k RA_s_k SU_s_k ///
		 CH_sc_k CV_sc_k DE_sc_k GU_sc_k HO_sc_k OR_sc_k RA_sc_k SU_sc_k ///		
		 , by(yrdec)
		 
*share of software devices
gen share_soft_mti = soft_dum_mti/counter
gen share_soft_key = soft_dum_key/counter
*share of cybersecurity content among those
gen share_cyber_mti = cybersec_dum_mti/soft_dum_mti
gen share_cyber_key = cybersec_dum_key/soft_dum_key
*same stats but w/in each AC:
foreach x in `acs'{
	gen `x'_share_soft_mti = `x'_s_m/`x'
	gen `x'_share_soft_key = `x'_s_k/`x'
	gen `x'_share_cyber_mti= `x'_sc_m/`x'_s_m
	gen `x'_share_cyber_key= `x'_sc_k/`x'_s_k	
	}
		 
* difference in means t-test for cybersecurity share in last 2 years of data vs. first 10:
gen year_cutoff = yrdec>=2014
replace year_cutoff = . if yrdec == 2012 | yrdec == 2013
ttest share_cyber_mti, by(year_cutoff)

drop year_cutoff

export excel using 1_by_year, replace firstrow(variables)


exit


