from logging import exception
from unittest import skip
import PySimpleGUI as sg
from itertools import count
import re
import pandas as pd
from urllib.parse import parse_qs, urlparse, urlsplit
import tldextract
import requests
import favicon
from bs4 import BeautifulSoup
import validators
import string
from tld import is_tld
from time import sleep
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
import urllib3
import pickle
import sklearn
import sklearn.ensemble._forest

def PhishingDetection(link):
    filename = "Phish_Random_Forest_Model.sav"
    loaded_model = pickle.load(open(filename, 'rb'))
# print("Input a link to scan: ")
# link = input()
# print("Scanning: " + link)

    urllib3.disable_warnings()
    sourcecode = requests.get(link, verify=False).text
    soup = BeautifulSoup(sourcecode, 'html.parser')

    countNumDots = len(re.findall("\.", link))
    countURLLength = len(link)
    countNumDash = len(re.findall("-", link))
    resultHostname = list(urlsplit(link))
    resultSubdomain = tldextract.extract(link)
    texttosplit = resultSubdomain.subdomain
    subdomainList = texttosplit.split(".")
    resultPath = urlparse(link).path
    resultQuery = urlparse(link).query

    pathtosplit = resultPath.split("/")
    httpsInHostname = urlparse(link).netloc

    countHttpsInHostname = 0
    if bool(re.search("https", httpsInHostname)) == True:
        countHttpsInHostname = 1
    else:
        countHttpsInHostname = 0

    if '@' in link:
        countAt = 1
    else:
        countAt = 0

    if '~' in link:
        countTilde = 1
    else:
        countTilde = 0

    countUnderscore = len(re.findall("_", link))
    countPercent = len(re.findall("%", link))
    countAmpersand = len(re.findall("\&", link))
    countHash = len(re.findall("#", link))
    countNumber = len(re.findall("\d", link))
    countHTTPS = len(re.findall("^http?://", link))

    countIpAddr = 0 
    if bool(re.search("((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])", link)) == True:
        countIpAddr = 1
    else:
        countIpAddr = 0

    countDoubleSlash = 0
    if bool(re.search("//", resultPath)) == True:
        countDoubleSlash = 1
    else:
        countDoubleSlash = 0
    countDashInHostname = len(re.findall("-", resultHostname[1]))
    countHostnameLength = len(resultHostname[1])
    countSubdomainLevel = len(subdomainList)
    countPathLevel = len(re.findall("/",resultPath))
    countPathLength = len(resultPath)
    countQueryLength = len(resultQuery)

    if countSubdomainLevel < 3:
        SubdomainLevelRT = -1
    elif countSubdomainLevel == 3:
        SubdomainLevelRT = 0
    elif countSubdomainLevel > 3:
        SubdomainLevelRT = 1

    if countURLLength < 54:
        URLLengthRT = -1
    elif 54 <= countURLLength <= 75:
        URLLengthRT = 0
    elif countURLLength > 75:
        URLLengthRT = 1

    #=====================================#
    # New Methode for Domain In subdomain #
    #=====================================#
    
    try:
        resultdomaininsubdomain = 0
        for i in range (0,len(subdomainList)):
            checktld = is_tld(subdomainList[i])
            if checktld == True:
                resultdomaininsubdomain += 1
        
        if resultdomaininsubdomain > 0:
            finalResultDomainInSubdomain = 1
        elif resultdomaininsubdomain == 0:
            finalResultDomainInSubdomain = 0
    except Exception as e:
        finalResultDomainInSubdomain = 0
        

    #================#
    # Domain In Path #
    #================#

    try:
        resultdomaininpath = 0

        for i in range (0,len(pathtosplit)):
            checktld = is_tld(pathtosplit[i])
            if checktld == True:
                resultdomaininpath += 1
        

        if resultdomaininpath > 0:
            finalResultDomainInPath = 1
        elif resultdomaininpath == 0:
            finalResultDomainInPath = 0
    except Exception as e:
        finalResultDomainInPath = 0

    #=====================#
    # ExtMetaScriptLinkRT #
    #=====================#

    try:
        countExtMetaScriptLink = 0
        countTotalMetaScriptLink = 0
        for metatag in soup.find_all('meta'):
            testmetatag = metatag.get('content')
            if testmetatag != None:
                if testmetatag.startswith(('http://', 'https://')):
                    countTotalMetaScriptLink += 1
                    extractMetaURL = tldextract.extract(testmetatag)
                    if resultSubdomain.domain == extractMetaURL.domain:
                        countExtMetaScriptLink += 0
                    elif resultSubdomain.domain != extractMetaURL.domain:
                        countExtMetaScriptLink += 1

        
        for scripttag in soup.find_all('script'):
            testscripttag = scripttag.get('src')
            if testscripttag != None:
                if testscripttag.startswith(('http://', 'https://')):
                    countTotalMetaScriptLink += 1
                    extractScriptURL = tldextract.extract(testscripttag)
                    if resultSubdomain.domain == extractScriptURL.domain:
                        countExtMetaScriptLink += 0
                    elif resultSubdomain.domain != extractScriptURL.domain:
                        countExtMetaScriptLink += 1               
        

        for linktag in soup.find_all('link'):
            testlinktag = linktag.get('href')
            if testlinktag != None:
                if testlinktag.startswith(('http://', 'https://')):
                    countTotalMetaScriptLink += 1
                    extractLinkURL = tldextract.extract(testlinktag)
                    if resultSubdomain.domain == extractLinkURL.domain:
                        countExtMetaScriptLink += 0
                    elif resultSubdomain.domain != extractLinkURL.domain:
                        countExtMetaScriptLink += 1

        
        if countTotalMetaScriptLink == 0:
            quickmaths3 = 0
        else:
            quickmaths3 = countExtMetaScriptLink / countTotalMetaScriptLink
        roundedMetaScriptLink = round(quickmaths3,6)

        PercentroundedMetaScriptLink = roundedMetaScriptLink * 100
        if PercentroundedMetaScriptLink < 20:
            resultMetaScriptLink = -1
        elif 20 <= PercentroundedMetaScriptLink <= 50:
            resultMetaScriptLink = 0
        elif PercentroundedMetaScriptLink > 50:
            resultMetaScriptLink = 1

    except Exception as e:
        resultMetaScriptLink = -1
        print(e)

    #====================#
    # PctExtResourceUrls #
    #====================#

    try:
        countExtObjectDomain = 0
        counttotalobject = 0
        tempRoundedPctObject = 0
        roundedPctObject = 0
        for objecturl in soup.find_all('object'):
            testobjecturl = objecturl.get('data')
            if testobjecturl != None:
                counttotalobject += 1
                if testobjecturl.startswith("http"):
                    tempobjecturl = tldextract.extract(testobjecturl)
                    if tempobjecturl.domain != resultSubdomain.domain:
                        countExtObjectDomain += 1
                    
            
            if counttotalobject == 0:
                quickPctMaths = 0
            else:
                quickPctMaths = countExtObjectDomain / counttotalobject
                roundedPctObject = round(quickPctMaths,6)

            tempRoundedPctObject = roundedPctObject * 100

        if tempRoundedPctObject < 22:
            PctExtResourceUrlsRT = -1
        elif 21 <= tempRoundedPctObject  <= 50:
            PctExtResourceUrlsRT = 0
        elif tempRoundedPctObject  > 50:
            PctExtResourceUrlsRT = 1
                        

    except Exception as e:
        roundedPctObject = 0
        PctExtResourceUrlsRT = -1
        print(e)

    try:
        roundedresultPctExtNull = 0
        quickmathsPctExtNull = 0
        counttotalurl = 0
        countexturl = 0
        countPctNullSelfRedirectHyperlinks = 0
        countFrequentDomainNameMismatch =  0
        counttotalurlxd = 0
        resultFrequentDomainNameMismatch = 0
        roundedresult = 0
        roundedresult2 = 0
        PctExtNullSelfRedirectHyperlinksRT = -1
        for exturl in soup.find_all('a'):
            resultexturl = exturl.get('href')

    #===================#
    # PctExtHyperlinks  #
    #===================#
            counttotalurl += 1
            tempExtUrl2 = tldextract.extract(resultexturl)

            if resultexturl != None:
                if resultexturl.startswith("http"):
                    counttotalurlxd += 1
                    if resultSubdomain.domain != tempExtUrl2.domain:
                        countexturl += 1
        #=============================#
        # FrequentDomainNameMismatch  #
        #=============================#
                    resultdomainonly = tldextract.extract(resultexturl)
                    if resultSubdomain.domain != resultdomainonly.domain:
                        countFrequentDomainNameMismatch += 1

                    halfcounttotalurl = counttotalurlxd / 2
                    
                    if countFrequentDomainNameMismatch > int(halfcounttotalurl):
                        resultFrequentDomainNameMismatch = 1
                    elif countFrequentDomainNameMismatch < int(halfcounttotalurl):
                        resultFrequentDomainNameMismatch = 0


    #================================#
    # PctNullSelfRedirectHyperlinks  #
    #================================#
                PctNullSelfRedirectHyperlinks0 = resultexturl.startswith("#")
                PctNullSelfRedirectHyperlinks1 = len(re.findall("about:blank", resultexturl))
                PctNullSelfRedirectHyperlinks2 = (len(resultexturl) == 0)
                PctNullSelfRedirectHyperlinks3 = resultexturl.startswith("javascript:void(0)")

                if PctNullSelfRedirectHyperlinks0 == True:
                    countPctNullSelfRedirectHyperlinks += 1
                if PctNullSelfRedirectHyperlinks1 > 0:
                    countPctNullSelfRedirectHyperlinks += 1
                if PctNullSelfRedirectHyperlinks2 > 0:
                    countPctNullSelfRedirectHyperlinks += 1
                if PctNullSelfRedirectHyperlinks3 == True:
                    countPctNullSelfRedirectHyperlinks += 1

                #==================================#
                # PctExtNullSelfRedirectHyperlinksRT  #
                #==================================#
                tempPctExtNullSelfRedirectHyperlinksRT = 0
                
                tempPctExtNullSelfRedirectHyperlinksRT = countPctNullSelfRedirectHyperlinks + countexturl

                # if tempPctExtNullSelfRedirectHyperlinksRT < 2:
                #     PctExtNullSelfRedirectHyperlinksRT = -1
                # elif tempPctExtNullSelfRedirectHyperlinksRT == 3:
                #     PctExtNullSelfRedirectHyperlinksRT = 0
                # elif tempPctExtNullSelfRedirectHyperlinksRT > 3:
                #     PctExtNullSelfRedirectHyperlinksRT = 1

        # Gw tab indent nya ngikutin yang bawah sry klo salah tolong cek lagi
        if counttotalurl == 0:
            quickmathsPctExtNull = 0
        else:
            quickmathsPctExtNull = tempPctExtNullSelfRedirectHyperlinksRT/counttotalurlxd
            roundedresultPctExtNull = round(quickmathsPctExtNull,6)
        
        PercentRoundedResultPctExtNull = roundedresultPctExtNull * 100

        if PercentRoundedResultPctExtNull < 31:
            PctExtNullSelfRedirectHyperlinksRT = -1
        elif 31 <= PercentRoundedResultPctExtNull <= 67:
            PctExtNullSelfRedirectHyperlinksRT = 0
        else:
            PctExtNullSelfRedirectHyperlinksRT = 1

    #===========================================#
    # Calculating Results for PctExtHyperlinks  #
    #===========================================#
        if counttotalurl == 0:
            quickmaths = 0
        else:
            quickmaths = countexturl/counttotalurlxd
            roundedresult = round(quickmaths,6)

    #=======================================================#
    # Calculating Results for PctNullSelfRedirectHyperlinks #
    #=======================================================#
        if counttotalurl == 0:
            quickmaths = 0
        else:
            quickmaths2 = countPctNullSelfRedirectHyperlinks/counttotalurl
            roundedresult2 = round(quickmaths2,6)

    except Exception as e:
        roundedresult = 0
        roundedresult2 = 0
        resultFrequentDomainNameMismatch = 0
        PctExtNullSelfRedirectHyperlinksRT = -1
        print(e)

    try:
        countAbnormalFormAction = 0
        countInsecureForm = 0
        countExternalURLform = 0
        countRelativeURL = 0
        resultAbnormalExtFormActionR = 0
        resultAbnormalFormAction = 0
        resultInsecureForm = 0
        resultExternalURLform = 0
        resultRelativeURLform = 0
        ALPHA = string.ascii_letters
        for test in soup.find_all('form'):
            resulttest = test.get('action')
            if resulttest != None:
                
    #===============#
    # ExtFormAction #
    #===============#
                if resulttest.startswith("http"):
                    tempExtFormAction = list(urlsplit(resulttest))
                    asdtest = tempExtFormAction[1]
                    if asdtest == resultHostname[1]:
                        countExternalURLform += 0
                    else:
                        countExternalURLform += 1

    #====================#
    # RelativeFormAction #
    #====================#
                # klo g salah lu bilangnya gini kan?
                #if resulttest.startswith(tuple(ALPHA)):
                tempRelativeFormAction = resulttest
                checkRelativeFormAction = list(urlsplit(resulttest))
            
                countRelativeURL += 1

                testidk123 = "https://" + checkRelativeFormAction[1]
        
                valid = validators.url(testidk123)
                

                if valid == True:
                    countRelativeURL -= 1


    #====================#
    # AbnormalFormAction #
    #====================#
                AbnormalFormAction = resulttest.startswith("#")
                AbnormalFormAction1 = len(re.findall("about:blank", resulttest))
                AbnormalFormAction2 = (len(resulttest) == 0)
                AbnormalFormAction3 = resulttest.startswith("javascript:true")

                if AbnormalFormAction == True:
                    countAbnormalFormAction += 1
                if AbnormalFormAction1 > 0:
                    countAbnormalFormAction += 1
                if AbnormalFormAction2 > 0:
                    countAbnormalFormAction += 1
                if AbnormalFormAction3 == True:
                    countAbnormalFormAction += 1

    #========================#
    # AbnormalExtFormActionR #
    #========================#
                if countAbnormalFormAction > 0:
                    resultAbnormalExtFormActionR = 1
                elif countExternalURLform > 0:
                    resultAbnormalExtFormActionR = 0
                else:
                    resultAbnormalExtFormActionR = -1


    #===============#
    # InsecureForms #
    #===============#
                insecureForm = len(re.findall("^http://", resulttest))
                if insecureForm > 0:
                    countInsecureForm += 1

    #========================================#
    # Convert results from numeric to binary #
    #========================================#
            if countAbnormalFormAction >= 1:
                resultAbnormalFormAction = 1
            elif countAbnormalFormAction == 0:
                resultAbnormalFormAction = 0

            if countInsecureForm >= 1:
                resultInsecureForm = 1
            elif countInsecureForm == 0:
                resultInsecureForm = 0
            
            if countExternalURLform >= 1:
                resultExternalURLform = 1
            elif countExternalURLform == 0:
                resultExternalURLform = 0
            
            if countRelativeURL >= 1:
                resultRelativeURLform = 1
            elif countRelativeURL == 0:
                resultRelativeURLform = 0

    except Exception as e:
        resultAbnormalExtFormActionR = -1
        resultAbnormalFormAction = 0
        resultInsecureForm = 0
        resultExternalURLform = 0
        resultRelativeURLform = 0
        print(e)

    try:

    #============#
    # ExtFavicon #
    #============#
        icons = favicon.get(link)
        resultFavicon = 0
        finalResultFavicon = 0
        for i in range(0,len(icons)):
            temp = list(urlsplit(icons[i].url))
            if temp[1] == resultHostname[1]:
                resultFavicon = resultFavicon + 0
            else:
                resultFavicon = resultFavicon + 1
        if resultFavicon >= 1:
            finalResultFavicon = 1
        elif resultFavicon == 0:
            finalResultFavicon = 0
    
    except Exception as e:
        finalResultFavicon = 0
        print(e)

    #==================#
    # ImageOnlyInForm #
    #==================#
    # mencari ImagesOnlyInForm, jika ada image dan tidak ada text sama sekali maka True
    countImageOnly = 0
    imageHtml = []
    textHtmlC = 0

    for formTag_ImageOnlyInForm in soup.find_all('form'):
        if formTag_ImageOnlyInForm != None:
            imageHtml = formTag_ImageOnlyInForm.get('img')
            textHtml = formTag_ImageOnlyInForm.get_text()
            textHtmlC = len(textHtml)
        else:
            countImageOnly = 0    

    if imageHtml != None and textHtmlC == 0:
        countImageOnly = 1
    else:
        countImageOnly = 0  


    #================#
    # Popup window #
    #================#
    # mencari popup di script
    script = soup.find_all('script')
    # regex untuk mencari popup
    pattern = re.compile("window\.open")
    pattern1 = re.compile("popup\(")
    pattern2 = re.compile("alert\(")
    pattern3 = re.compile("confirm\(")
    pattern4 = re.compile("prompt\(")
    listing = []
    listing1 = []
    listing2 = []
    listing3 = []
    listing4 = []

    # merubah format BS ke list
    for x in script:
        listing.append(str(x))
        listing1.append(str(x))
        listing2.append(str(x))
        listing3.append(str(x))
        listing4.append(str(x))

    newListing = list(filter(pattern.search, listing))
    newListing1 = list(filter(pattern1.search, listing1))
    newListing2 = list(filter(pattern2.search, listing2))
    newListing3 = list(filter(pattern3.search, listing3))
    newListing4 = list(filter(pattern4.search, listing4))

    newListingC = len(newListing)
    newListing1C = len(newListing1)
    newListing2C = len(newListing2)
    newListing3C = len(newListing3)
    newListing4C = len(newListing4)

    countPopup = 0

    if newListingC + newListing1C + newListing2C + newListing3C + newListing4C == 0:
        countPopup = 0
    else:
        countPopup = 1

    # print(countPopup)

    #Menurut chiew2019: "Brand name here is assumed as the most frequent domain name in the webpage HTML content."

    #function untuk mencari element yang paling banyak disuatu list
    def most_frequent(List):
        counter = 0
        num = List[0]
        
        for i in List:
            curr_frequency = List.count(i)
            if(curr_frequency> counter):
                counter = curr_frequency
                num = i
    
        return num


    #EmbeddedBrandName
    extract_url = tldextract.extract(link)
    domain_url = extract_url.domain

    options = Options()
    options.add_argument('--allow-running-insecure-content')
    options.add_argument('--ignore-certificate-errors')
    options.headless = True

    PATH = 'C:\Program Files (x86)\chromedriver.exe'
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    driver.get(link)
    sleep(5)

    #Mencari hyperlink diseluruh webpage dan masukkan ke list (untuk dicompare domainnya)
    elems = driver.find_elements(By.TAG_NAME, "a")
    list_domain = []
    for elm in elems:
        href = elm.get_attribute("href")
        if href is not None:
            extract = tldextract.extract(href)
            domain = extract.domain
            list_domain.append(domain)

    #Jika domain sekarang dan domain yang paling sering muncul di webpage. Dianggap True
    # elems = driver.find_elements(By.TAG_NAME, "a")
    # list_domain = []
    # for elm in elems:
    #     href = elm.get_attribute("href")
    #     if href is not None:
    #         extract = tldextract.extract(href)
    #         domain = extract.domain
    #         list_domain.append(domain)

    #Jika domain sekarang dan domain yang paling sering muncul di webpage. Dianggap True
    # if domain_url == most_frequent(list_domain):
    #     countExcelBrandName = 1
    # else:
    #     countExcelBrandName = 0
    if not list_domain:
        countExcelBrandName = 0
    else:
        if domain_url == most_frequent(list_domain):
            countExcelBrandName = 1
        else:
            countExcelBrandName = 0

    #iframeorframe
    countIframe = 0
    iframe = driver.find_elements(By.TAG_NAME, 'iframe')
    for value in iframe:
        countIframe +=1

    if countIframe > 0:
        countExcelIframe = 1
    else:
        countExcelIframe = 0

    #missingtitle
    if driver.title is None:
        countExcelMissingTitle = 1
    else:
        countExcelMissingTitle = 0

    #numquerycomponents
    parsed_url = urlparse(link)
    query = parse_qs(parsed_url.query)
    query_count = len(query)


    #numsensitivewords
    countSens = 0
    if "secure" in link:
        countSens += 1
    if "account" in link:
        countSens += 1
    if "webscr" in link:
        countSens += 1
    if "login" in link:
        countSens += 1
    if "ebayisapi" in link:
        countSens += 1
    if "signin" in link:
        countSens += 1
    if "banking" in link:
        countSens += 1
    if "confirm" in link:
        countSens += 1

    #randomstring
    countRandomString = 0 
    url_check = bool(re.search('[a-zA-Z]', link))
    if url_check == True:
        countRandomString += 1
    url_check2 = bool(re.search('[0-9]', link))
    if url_check2 == True:
        countRandomString += 1

    if countRandomString == 2:
        countExcelRandomString = 1
    else:
        countExcelRandomString = 0

    #rightclickdisabled
    elemRightclick = driver.find_elements(By.TAG_NAME, 'script')

    countRightclick = 0
    for lnk in elemRightclick:
        #menurut [17] disuruh cek "event.button == 2" harus ditest dulu ke web yg g bisa rightclick
        if "event.button == 2" in lnk.get_attribute('outerHTML'):
            countRightclick += 1
        if "contextmenu" and "preventDefault" in lnk.get_attribute('outerHTML'):
            countRightclick += 1

    if countRightclick == 2:
        countExcelRightClick = 1
    else:
        countExcelRightClick = 0

    # print(countRightclick)

    #submitinfotoemail
    lnksSubmitemail = driver.find_elements(By.TAG_NAME, "a")
    countEmail = 0
    for lnk in lnksSubmitemail:
        hrefEmail = lnk.get_attribute('href')
        if hrefEmail is not None:
            if 'mailto' in lnk.get_attribute('href'):
                countEmail += 1
    
    if countEmail > 0:
        countExcelEmail = 1
    else:
        countExcelEmail = 0

    #fakelinkinstatusbar
    page_sourceFakelink = driver.page_source

    search_onmouseover = driver.find_elements(By.XPATH, '//*[@onmouseover]')

    if not search_onmouseover:
        countExcelFakeLink = 0
    else:
        for elem in page_sourceFakelink:
            if "window.status" in elem:
                countExcelFakeLink = 1
            else:
                countExcelFakeLink = 0




    # print(". in URL: ", countNumDots)
    # print("URL Length: ", countURLLength)
    # print("- in URL: ", countNumDash)
    # print("@ in URL: ", countAt)
    # print("~ in URL: ", countTilde)
    # print("_ in URL: ",  countUnderscore)
    # print("% \in URL: ", countPercent)
    # print("& in URL: ", countAmpersand)
    # print("# in URL: ", countHash)
    # print("Numeric character in URL: ", countNumber)
    # print("HTTP in URL: ", countHTTPS)
    # print("IP Address in URL:", countIpAddr)
    # # print("Path length: ", countPathL)
    # print("// in URL: ", countDoubleSlash)
    # print("- in Hostname: ", countDashInHostname)
    # print("Hostname Length: ",countHostnameLength)
    # print("Subdomain Level: ",countSubdomainLevel)
    # print("Path Level: ",countPathLevel)
    # print("Path Length: ",countPathLength)
    # print("Query Length", countQueryLength)
    # print("Favicon loaded from external domain: ",  finalResultFavicon)
    # print("AbnormalFormActions founded: ", resultAbnormalFormAction)
    # print("InsecureForms founded: ", resultInsecureForm)
    # print("ExtFormAction founded: ", resultExternalURLform)

    atr = {
        "NumDots": [countNumDots],
        "SubdomainLevel": [countSubdomainLevel],
        "PathLevel": [countPathLevel],
        "UrlLength": [countURLLength],
        "NumDash": [countNumDash],
        "NumDashInHostname": [countDashInHostname],
        "AtSymbol": [countAt],
        "TildeSymbol": [countTilde],
        "NumUnderscore": [countUnderscore],
        "NumPercent": [countPercent],
        "NumQueryComponents": [query_count],
        "NumAmpersand": [countAmpersand],
        "NumHash": [countHash],
        "NumNumericChars": [countNumber],
        "NoHttps": [countHTTPS],
        "RandomString": [countExcelRandomString],
        "IpAddress": [countIpAddr],
        "DomainInSubdomains": [finalResultDomainInSubdomain],
        "DomainInPaths": [finalResultDomainInPath],
        "HttpsInHostname": [countHttpsInHostname],
        "HostnameLength": [countHostnameLength],
        "PathLength": [countPathLength],
        "QueryLength": [countQueryLength],
        "DoubleSlashInPath": [countDoubleSlash],
        "NumSensitiveWords": [countSens],
        "EmbeddedBrandName": [countExcelBrandName],
        "PctExtHyperlinks": [roundedresult],
        "PctExtResourceUrls": [roundedPctObject],
        "ExtFavicon": [finalResultFavicon],
        "InsecureForms": [resultInsecureForm],
        "RelativeFormAction": [resultRelativeURLform],
        "ExtFormAction": [resultExternalURLform],
        "AbnormalFormAction": [resultAbnormalFormAction],
        "PctNullSelfRedirectHyperlinks": [roundedresult2],
        "FrequentDomainNameMismatch": [resultFrequentDomainNameMismatch],
        "FakeLinkInStatusBar": [countExcelFakeLink],
        "RightClickDisabled": [countExcelRightClick],
        "PopUpWindow": [countPopup],
        "SubmitInfoToEmail": [countExcelEmail],
        "IframeOrFrame": [countExcelIframe],
        "MissingTitle": [countExcelMissingTitle],
        "ImagesOnlyInForm": [countImageOnly],
        "SubdomainLevelRT": [SubdomainLevelRT],
        "UrlLengthRT": [URLLengthRT],
        "PctExtResourceUrlsRT": [PctExtResourceUrlsRT],
        "AbnormalExtFormActionR": [resultAbnormalExtFormActionR],
        "ExtMetaScriptLinkRT": [resultMetaScriptLink],
        "PctExtNullSelfRedirectHyperlinksRT": [PctExtNullSelfRedirectHyperlinksRT]
        }
    driver.quit()
    data = pd.DataFrame(atr)
    result = loaded_model.predict(data)
    # print(result)
    return result

# data = pd.DataFrame(atr)
# filepath = 'Phishing_Dataset_test.xlsx'
# path = Path(filepath)

# if path.is_file() == False:
#     data.to_excel('Phishing_Dataset_test.xlsx', sheet_name='sheet1', index=False, header=True)
# else:
#     with pd.ExcelWriter('Phishing_Dataset.xlsx', mode='a', engine='openpyxl', if_sheet_exists='overlay') as writer:  
#         data.to_excel(writer, sheet_name='sheet1', startrow=writer.sheets['sheet1'].max_row, index = False, header=False)

sg.theme('LightBlue')

output = sg.Text()

layout = [  [sg.Text('Web Phishing Detection with 48 Indicators')],
            [sg.Text('Enter link to be scanned:'), sg.InputText()],
            [output],
            [sg.Button('Scan'), sg.Button('Exit')] ]


window = sg.Window('DefPhish', layout)

while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == 'Exit':
        break
    result = PhishingDetection(values[0])
    if result == 1:  
        output.update(value="The Website is a Phishing Website")
    elif result == 0:  
        output.update(value="The Website is a Legitimate Website")   
    # print('You entered ', values[0])

window.close()