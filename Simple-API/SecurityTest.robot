*** Settings ***
Library  ThreatPlaybook  Customer API
Library  Collections
Library  RoboZap  http://127.0.0.1:8090/  8090
Library  RoboNmap
Library  RoboWFuzz  /Users/abhaybhargav/Documents/Code/Python/RoboWFuzz/lists/directory-list-1.0.txt
Library  REST  http://localhost:5050  proxies={"http": "http://127.0.0.1:8090", "https": "http://127.0.0.1:8090"}

*** Variables ***
${TARGET_NAME}  CRM_Application
${TARGET_URI}  localhost:5050
${TARGET_HOST}  localhost
#CONFIG
${RESULTS_PATH}  /Users/abhaybhargav/Documents/Code/Python/TPExample/Simple-API/results

#WFUZZ
${WFUZZ_FILE}  directory_brute.json

#ZAP
${ZAP_PATH}  /Applications/OWASP_ZAP.app/Contents/Java/
${APPNAME}  Flask API
${CONTEXT}  Flask_API
${REPORT_TITLE}  Flask API Test Report - ZAP
${REPORT_FORMAT}  json
${ZAP_REPORT_FILE}  flask_api.json
${REPORT_AUTHOR}  Abhay Bhargav
${SCANPOLICY}  Light


*** Test Cases ***
Manage Entities
    load entity file
    find or create entities
    find or connect entities

load_test_cases
    process test cases

generate threat models
    find or load cases from directory  link_tests=True

Create Targets
    find or create target  ${TARGET_NAME}  ${TARGET_URI}


Port Scan and Service Enumeration
    nmap default scan  ${TARGET_HOST}  file_export=${RESULTS_PATH}/flask.txt
    nmap print results
    create and link recon  nmap  ${TARGET_NAME}  file_name=${RESULTS_PATH}/flask.txt  tags=nmap,

Directory Bruteforce
    [Timeout]  30 seconds
    brute_directories  http://${TARGET_URI}/FUZZ  concur=3  file_name=${RESULTS_PATH}/${WFUZZ_FILE}

Link Dir Brute Result
    create and link recon  wfuzz  ${TARGET_NAME}  file_name=${RESULTS_PATH}/${WFUZZ_FILE}  tags=wfuzz,

Initialize ZAP
    [Tags]  zap_init
    start gui zap  ${ZAP_PATH}
    sleep  10
    zap open url  http://${TARGET_URI}

Authenticate to Web Service ZAP
    &{res}=  POST  /login  {"username": "admin", "password": "admin123"}
    Integer  response status  200
    set suite variable  ${TOKEN}  ${res.headers["Authorization"]}

Get Customer by ID
    [Setup]  Set Headers  { "Authorization": "${TOKEN}" }
    GET  /get/2
    Integer  response status  200

Post Fetch Customer
    [Setup]  Set Headers  { "Authorization": "${TOKEN}" }
    POST  /fetch/customer  { "id": 3 }
    Integer  response status  200

Search Customer by Username
    [Setup]  Set Headers  { "Authorization": "${TOKEN}" }
    POST  /search  { "search": "dleon" }
    Integer  response status  200

ZAP Contextualize
    [Tags]  zap_context
    ${contextid}=  zap define context  ${CONTEXT}  http://${TARGET_URI}
    set suite variable  ${CONTEXT_ID}  ${contextid}

ZAP Active Scan
    [Tags]  zap_scan
    ${scan_id}=  zap start ascan  ${CONTEXT_ID}  http://${TARGET_URI}  ${SCANPOLICY}
    set suite variable  ${SCAN_ID}  ${scan_id}
    zap scan status  ${scan_id}

ZAP Generate Report
    [Tags]  zap_generate_report
    zap export report  ${RESULTS_PATH}/${ZAP_REPORT_FILE}  ${REPORT_FORMAT}  ${REPORT_TITLE}  ${REPORT_AUTHOR}

ZAP Die
    [Tags]  zap_kill
    zap shutdown
    sleep  3

Write ZAP Results to DB
    parse zap json  ${RESULTS_PATH}/${ZAP_REPORT_FILE}  ${TARGET_NAME}

Generate Threat Maps
    generate threat maps

Write Final Report
    write markdown report