#!/usr/bin/env python3
import argparse
import json
import requests
import uuid as _uuid
import img2pdf
import tempfile
import os
import shutil
import time
from multiprocessing import Process
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def requestRefreshToken():
    global token
    global refreshToken
    print("Refreshing token")
    httpRequestRefreshToken = requests.post("http://80.81.152.155:8085/api/v2/users/refresh",
        headers = {'Content-Type': 'application/json'},
        json = {"token": token, "refreshToken": refreshToken})
    requestRefreshTokenJSONResponse = json.loads(httpRequestRefreshToken.content)
    del httpRequestRefreshToken
    try:
        token = requestRefreshTokenJSONResponse['token']
        refreshToken = requestRefreshTokenJSONResponse['refreshToken']
        print("Success at refreshing token")
    except KeyError:
        print("Failure at refreshing token")
    del requestRefreshTokenJSONResponse

def crdpDecryptor(folder):
    aad = None
    # AES-128 = 32 chars, AES-256 = 64 chars (hex expression)
    key = 'ha31ebFbckaegBc1e4daD35safP15Rvh'
    aesgcm = AESGCM(key.encode('utf-8'))

    for filename in os.listdir(folder):
        filename = os.path.join(folder, filename)

        with open(filename, 'rb') as infile:
            nonce = infile.read(12)
            outfile = open(filename + ".dec", 'wb+')
            while True:
                # 2**20 % 16 bytes (128-bits) = 0... so it's fine
                chunk = infile.read(2 ** 20)
                if not chunk: break
                outfile.write(aesgcm.decrypt(nonce, chunk, aad))
            del nonce
            del outfile
            del chunk
        os.rename(filename + ".dec", filename)
    del aad
    del key
    del aesgcm
    del filename

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CRDP Book Downloader")
    parser.add_argument('-l', '--language', help='set language (either en or fr or ar) (default en)', default='en')
    parser.add_argument('-g', '--grade', help='limit results to only grade')
    parser.add_argument('-d', '--download', help='specify which id to download, for all use __all__')
    parser.add_argument('-o', '--output', help='output path', default=os.getcwd())
    args = parser.parse_args()
    del parser

    requestToMakeAccount = requests.post("http://80.81.152.155:8085/api/v2/users/teacher",
        headers = {'Content-Type': 'application/json'},
        json = {
            "role":"teacher",
            "language":args.language,
            "grades":["KG1","KG2","KG3","Gr1","Gr2","Gr3","Gr4","Gr5","Gr6","Gr7","Gr8","Gr9","S1","S2S","S2L","S3LH","S3SE","S3LS","S3GS"],
            "deviceId":str(_uuid.uuid4())
        }
    )
    responseToMakeAccountJSON = json.loads(requestToMakeAccount.content)
    del requestToMakeAccount
    token = responseToMakeAccountJSON['token']
    refreshToken = responseToMakeAccountJSON['refreshToken']
    del responseToMakeAccountJSON

    listOfBooksRequest = requests.get("http://80.81.152.155:8085/api/v1/books/language/" + args.language,
        headers = {'Accept': 'application/json', 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'} )
    responseListOfBooksJSON = json.loads(listOfBooksRequest.content)
    del listOfBooksRequest

    if args.download is not None:
        class UUIDFound(Exception): pass
        if args.download == "__all__":
            args.download = []
            for classGrade in responseListOfBooksJSON['result']:
                for book in responseListOfBooksJSON['result'][classGrade]: args.download += [ book['Id'] ]
            # Remove duplicates so we don't download twice
            args.download = list(dict.fromkeys(args.download))
            del classGrade
            del book
        else:
            args.download = args.download.split(" ")

        for uuid in args.download:
            print ("Downloading %s" % uuid)
            while True:
                bookDataZipRequest = requests.get("http://80.81.152.155:8085/api/v1/books/download/" + uuid,
                    stream = True,
                    headers = {
                        'Accept': 'application/json',
                        'Authorization': 'Bearer ' + token,
                        'Content-Type': 'application/json'
                    }
                )
                if bookDataZipRequest.status_code != 200:
                    requestRefreshToken()
                else:
                    break
            bookDataZipFile = tempfile.NamedTemporaryFile(delete=False)
            shutil.copyfileobj(bookDataZipRequest.raw, open(bookDataZipFile.name, 'wb'))
            del bookDataZipRequest
            with tempfile.TemporaryDirectory() as extractedBookDataZip:
                shutil.unpack_archive(bookDataZipFile.name, extractedBookDataZip, 'zip')
                os.remove(bookDataZipFile.name)
                del bookDataZipFile
                crdpDecryptor(extractedBookDataZip)
                with tempfile.NamedTemporaryFile(delete=False) as pdf:
                    # This is needed because Pillow has memory leaks
                    p = Process(
                            target=pdf.write,
                            args=(
                                img2pdf.convert(
                                    [os.path.join(extractedBookDataZip, i) for i in sorted(os.listdir(extractedBookDataZip), key=lambda x: int(x.split('.')[0]))]
                                ),
                        )
                    )
                    p.start()
                    while p.is_alive():
                        time.sleep(0.001)
                    p.terminate()
                    p.close()
                    del p
            del extractedBookDataZip
            try:
                for classGrade in responseListOfBooksJSON['result']:
                    for book in responseListOfBooksJSON['result'][classGrade]:
                        if book['Id'] == uuid: raise UUIDFound
            except UUIDFound:
                filebase = classGrade + ' - ' + book['Title']
                finalFile=os.path.join(args.output, filebase + '.pdf')
                tryToGetAvailFile=1
                while os.path.isfile(finalFile):
                    finalFile = os.path.join(args.output, filebase + ' (' + str(tryToGetAvailFile) + ')' +'.pdf')
                    tryToGetAvailFile+=1
                shutil.copyfile(pdf.name, finalFile)
                os.remove(pdf.name)
                print ("Done %s" % uuid)
                del pdf
                del classGrade
                del book
                del finalFile
                del tryToGetAvailFile
                del filebase
    else:
        for classGrade in sorted(responseListOfBooksJSON['result']):
            if args.grade is not None:
                if args.grade.lower() != classGrade.lower(): continue
            print ("%s:" % classGrade)
            for book in responseListOfBooksJSON['result'][classGrade]:
                print ("  %s" % book['Title'])
                print ("  %s" % book['Id'])
                print ("  %s" % book['Cover'])
                print ()
