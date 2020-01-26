from flask import render_template, request, Flask, redirect, url_for

#import pymysql
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5
from datetime import datetime as DT
import hmac
import warnings
from Crypto.Cipher import AES
from merklelib import MerkleTree
warnings.filterwarnings("ignore")
import random
N = 0
dtKey = "sixteen--SIXTEEN"
dList = []
#Block Class
invalidTxns=[]
outIndex=[]

class block:
    blockCount=0
    def __init__(self,pH,txnList,PoW,mR,miner):
        block.blockCount+=1
        self.blockNo=block.blockCount
        self.prevHash=pH
        self.transactions=txnList
        self.timestamp=DT.timestamp(DT.now())
        self.hash=PoW['Hash']
        self.nonce=PoW['nonce']
        self.mRoot=mR
        self.miner=miner
    
    def getBlockDetails(self):
        print("Block#:",self.blockNo)
        print("previous HASH:",self.prevHash)
        print("current HASH:",self.hash)
        print()
        
        print("Transactions:",len(self.transactions),"     Time:",DT.fromtimestamp(self.timestamp))
        for T in self.transactions:
            print("Sender:",T['Sender'].id, end=",  ")
            print("Receiver:",T['Receiver'].id, end=",  ")
            print("Amount:",T['Amount'])
        
        print("Merkley Root:",self.mRoot)
        print("\nNONCE:",self.nonce)
        print("Miner:",self.miner.address)   # NEW ATTRIBUTE

#Device class
class device:
    deviceCount = 0
    
    def __init__(self):
        self.id = device.deviceCount
        self.sk,self.pk= self.getKeys()
        self.balance=100
        
        self.idProof = {}
        self.idProof['public_KEY'] = self.pk.hex()
        self.idProof['block_no'] = None
        self.idProof['block_hash'] = None
        self.idProof['difficulty'] = None
        self.idProof['txn_Index'] = None
        self.idProof['Node_ID'] = None
        self.idProof['okToSend'] = None
        self.idProof['okToRecieve'] = None
        self.confi=0.5
        self.resi=100
        self.txncount=0
        self.D=0.01
        
        data=str(self.id)+self.pk.hex()
        self.address=SHA.new(data.encode()).hexdigest()
        device.deviceCount += 1
    
    def getKeys(self):
        self.keypair=RSA.generate(1024)
        sk = self.keypair.exportKey('DER')
        pk = self.keypair.publickey().exportKey('DER')
        return sk,pk
    
    def getDeviceDetails(self):
        print("deviceID: "+str(self.id),"publicKEY:",self.pk.hex(),"deviceADDRESS:",self.address,sep="\n",end="\n\n")
        
    @classmethod
    def transact(self, S,R,amt):
        
        if amt < dList[S.id].balance:
            dList[S.id].balance-=amt
            dList[R.id].balance+=amt
            Txn= S.address+R.address+str(amt)
            sign = device.signTxn(Txn,S.sk)
            verified = device.verifyTxn(Txn, sign, S.pk)
            if(verified):
                print("Transaction is verified")
                if dList[S.id].resi>0:
                    dList[S.id].resi-=(random.randint(1,2)/100)
                    dList[S.id].txncount+=1
                    return [{"Sender":S,"Receiver":R,"Amount":amt}]
                else:
                    dList[S.id].resi=0
                return []
            else:
                invalidTxns.append({"Sender":dList[S],"Receiver":dList[R],"Amount":amt,"status":"TxnNotVerified"})
                print("Fraudulent transaction")
                return []
        else:
            invalidTxns.append({"Sender":S.id,"Receiver":R.id,"Amount":amt,"status":"TxnNotVerified"})
            print("Sybil node")
            return []

    @classmethod
    def dataTransfer(self,S,R,msg,dtKEY):
        sF,rF=device.checkID(S,R)
        if(not sF):
            # invalidTxns.append({"Sender":S,"Receiver":R,"Amount":msg,"status":"SenderIDNotVerified"})
            return ["Sender ID cannot be verified, Possible Sybil Threat"]
        elif(not rF):
            # invalidTxns.append({"Sender":S,"Receiver":R,"Amount":msg,"status":"ReceiverIDNotVerified"})
            return ["Receiver ID cannot be verified, Possible Sybil Threat"]
        else:
            S.resi-=(random.randint(1,2)/100)
            pad=16-len(msg)%16
            msg=msg.zfill(pad+len(msg))
            secret=AES.new(dtKEY)
            cipherTxt=secret.encrypt(msg)
            signature=device.signTxn(cipherTxt,S.sk)
            S.txncount+=1
            return [S,R,cipherTxt,signature]
        return None
        
    @classmethod
    def checkID(self, S, R):
        SID=S.idProof
        RID=R.idProof
        sF,rF=True,True    #F-> flag
        for i in SID.values():
            er="Success"
            if(i is None):
                sF=False
                # invalidTxns.append({"Sender":S,"Receiver":R,"Amount":A,"status":"SenderIDNotVerified"})
                er = "Sender ID cannot be verified Possible Sybil Threat" 
                print("Sender ID cannot be verified")
                break
        for i in RID.values():
            if(i is None):
                rF=False
                # invalidTxns.append({"Sender":S,"Receiver":R,"Amount":A,"status":"ReceiverNotVerified"})
                er =" Receiver ID cannot be verified Possible Sybil Threat"
                print("Receiver ID cannot be verified")
                break
        
        return (sF,rF)               
    
    @classmethod
    def signTxn(self,txn, sk):
        txn=str(txn)
        RSA_key=RSA.importKey(sk)
        author=PKCS1_v1_5.new(RSA_key)
        msg=SHA.new(txn.encode())
        signature = author.sign(msg)
        return signature
    
    @classmethod
    def verifyTxn(self, txn, sign, pk):
        txn=str(txn)
        msg=SHA.new(txn.encode())
        RSA_key=RSA.importKey(pk)
        verifier = PKCS1_v1_5.new(RSA_key)
        verified=verifier.verify(msg, sign)
        return verified
    
    def __del__(self):
        print("Device:",self.id,"deleted")
        device.deviceCount-=1

#blockchain Class
def HF(data):
    data=data.hex()
    return SHA.new(data.encode()).hexdigest()

class blockChain:
    chain=[]
    allTxns={}
    Tcount=1
    def __init__(self,H):
        pH='0'
        PoW={}
        txn=[{"Sender":H,"Receiver":H,"Amount":0}]
        PoW['Hash'],PoW['nonce']=self.PoW(pH,txn)
        mR=SHA.new(str(txn).encode()).hexdigest()
        txID = str(1)
        diff=3
        H.idProof['block_no'] = len(blockChain.chain)
        H.idProof['block_hash'] = PoW['Hash']
        H.idProof['difficulty'] = diff
        H.idProof['txn_Index'] = txID
        pk=H.pk
        key=hmac.HMAC(pk)
        H.idProof['Node_ID'] = hmac.HMAC(key.digest(),txID.encode()).hexdigest()
        H.idProof['okToSend'] = '0'
        H.idProof['okToRecieve'] = '0'
        
        miner=H
        BLOC=block(pH,txn,PoW,mR,miner)
        blockChain.chain.append(BLOC)
        
        
    def newBlock(self,txn):
        if(txn==[]):
            return
        
        Tno="Txn-"+str(blockChain.Tcount)
        blockChain.allTxns[Tno]=txn[0]
        blockChain.Tcount+=1
        pH=blockChain.chain[-1].hash
        PoW={}
        PoW['Hash'],PoW['nonce']=self.PoW(pH,txn)
        mT=MerkleTree(txn, HF)
        mR=mT.merkle_root
        #ID PROOF GENERATION
        S = txn[0]['Sender']
        txID = str(1)
        diff=3
        S.idProof['block_no'] = len(blockChain.chain)
        S.idProof['block_hash'] = PoW['Hash']
        S.idProof['difficulty'] = diff
        S.idProof['txn_Index'] = txID
        pk=S.pk
        key=hmac.HMAC(pk)
        S.idProof['Node_ID'] = hmac.HMAC(key.digest(),txID.encode()).hexdigest()
        S.idProof['okToSend'] = '0'
        S.idProof['okToRecieve'] = '0'
        
        miner=blockChain.POC()
        BLOC=block(pH,txn,PoW,mR,miner)
        blockChain.chain.append(BLOC)
        
    def addNewBlock(self,txnList):
        if(txnList==[]):
            return
        
        for T in txnList:
            Tno="Txn-"+str(blockChain.Tcount)
            blockChain.allTxns[Tno]=T
            blockChain.Tcount+=1
            
        pH=blockChain.chain[-1].hash
        PoW={}
        PoW['Hash'],PoW['nonce']=self.PoW(pH,txnList)        
        mT = MerkleTree(txnList, HF)
        mR=mT.merkle_root
        miner=blockChain.POC()
        BLOC=block(pH,txnList,PoW,mR,miner)
        blockChain.chain.append(BLOC)
        
    @classmethod 
    def POC(self):
        maxr=0
        maxt=0
        for i in range(N):
            if dList[i].resi>=dList[maxr].resi:
                maxr=i
            if dList[i].txncount>=dList[maxt].txncount:
                maxt=i
        print(maxr)
        print(maxt)
        confi=[]
        for i in range(N):
            dList[i].confi= (dList[i].confi*(1-dList[i].D))+ ((dList[i].txncount/dList[maxt].txncount)*(dList[i].resi/dList[maxr].resi))
            confi.append(dList[i].confi)
            
        idx=confi.index(max(confi))
        maxco=dList[idx].confi
        for i in range(N):
            dList[i].confi=dList[i].confi/maxco
            if(dList[i].confi==1):
                t=i
        for i in range(N):
            dList[i].txncount=0
        return dList[t]
        
    
    def PoW(self,pH,txn,diff=2):
        nonce=0
        data=pH+str(txn)+str(nonce)
        nH=SHA.new(data.encode()).hexdigest()
        while nH[:diff] != '0'*diff:
            nonce += 1
            data=pH+str(txn)+str(nonce)
            nH=SHA.new(data.encode()).hexdigest()
        return nH,nonce
    
    def getChainDetails(self):
        for D in blockChain.chain:
            D.getBlockDetails()
            print("-------------------------------------------")

#flask Section
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

myChain = None

@app.route('/', methods=['POST'])
def getvalue():
    globals()['N'] = int(request.form['Users'])
    dL=[]
    for i in range(N):
        dL.append(device())
    
    # Database Connection
    # mydb = pymysql.connect(host="localhost", user="root", passwd="", database="djbase")
    # cursor = mydb.cursor()

    # for i in range(N):
    #     insert = "INSERT INTO wallets (publicKEY,privateKEY) values(%s,%s)"
    #     values = (dL[i].pk, dL[i].sk)
    #     cursor.execute(insert, values)
    # mydb.commit()
    globals()['dList']=dL
    global myChain
    myChain =blockChain(dList[0])
    return render_template('table.html', j=dList)

@app.route('/alltxns')
def allt():
    return render_template('alltxns.html',chain=myChain)

@app.route('/transaction')
def inde():
    return render_template('transaction.html', l = N)

#block chain creation
tc = 1

@app.route('/result', methods=['POST','GET'])
def getvalued():
    S = int(request.form['sender'])
    R = int(request.form['receiver'])
    A = int(request.form['amount'])
    if(S>=len(dList)):
        status="SenderNotFound, "
    elif(S==0):
        status="Invalid Sender, "
    elif(R!=0):
        status="Invalid Receiver, "
    if(0<S<N and R== 0):  
        BLOC = device.transact(dList[S], dList[R], A)
        myChain.newBlock(BLOC)
    else:
        if(0<S<N and 0<=R<N):
            invalidTxns.append({"Sender":dList[S],"Receiver":dList[R],"Amount":A,"status":status+"setupFailed"})
        else:
            outIndex.append({"Sender":S,"Receiver":R,"Amount":A,"status":status+"setupFailed"})
    globals()['tc'] = globals()['tc'] + 1
    if (globals()['tc'] >= globals()['N']):
        myChain.getChainDetails()
        return render_template('result.html', chain = myChain.chain)
    return redirect(url_for('inde'))
verfi = ""
@app.route('/proof')
def proof():
    return render_template('proof.html', D=dList)

@app.route('/datatxns')
def dtxns():
    return render_template('datatxns.html', l = N, v = verfi)
txn = []
@app.route('/res', methods=['POST', 'GET'])
def gettxns():
    S = int(request.form['sender'])
    R = int(request.form['receiver'])
    Msg = request.form['amount']
    print("Dtxns \nSender: " , S ,  " Receiver: " , R , " Msg: " , Msg)

    if(0<=S<N and 0<=R<N):
        if(dList[S].resi==0 or dList[R].resi==0):
            print("Device dead!")
        else:
            data = device.dataTransfer(dList[S], dList[R], Msg, dtKey) 
            if(len(data)==4):
                verified = device.verifyTxn(data[2], data[3],data[0].pk)
                print(data[0].address ,  data[1].address ,  data[2].hex() )
                if(verified):
                    txn.append({"Sender": data[0], "Receiver": data[1], "Amount": data[2].hex() })
                    ack = "Transaction Success"
                if(len(txn) == 2):
                    myChain.addNewBlock(txn)
                    globals()['txn'] = []
            
            else:
                invalidTxns.append({"Sender":dList[S],"Receiver":dList[R],"Amount":Msg,"status":data[0]})
                ack=data[0]
    else:
        outIndex.append({"Sender":S,"Receiver":R,"Amount":Msg,"status":"Sender/Receiver not in Network"})
        ack="Sender/Receiver not in Network"       
    globals()['verfi']=ack
    return redirect(url_for('dtxns'))

@app.route('/bloc', methods=['POST','GET']) 
def priBloc():
    return render_template('result.html', chain = myChain.chain)

@app.route('/invalid')
def inval():
    return render_template('invalid.html', i = invalidTxns, o = outIndex )

if __name__ == '__main__':
    app.run()