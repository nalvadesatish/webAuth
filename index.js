const express=require('express');
const crypto=require('node:crypto');
const {generateRegistrationOptions,verifyRegistrationResponse,generateAuthenticationOptions, verifyAuthenticationResponse} = require('@simplewebauthn/server');


if(!globalThis.crypto){
    globalThis.crypto=crypto;
}

const PORT=3000;

const app=express();

app.use(express.static("./public"));
app.use(express.json());

const userStore={};
const challengeStore={};
app.post('/register',(req,res)=>{
    const {userName,passWord}=req.body;
    const id=`user_${Date.now()}`
    const user={
        id,
        userName,
        passWord,
    }
    userStore[id]=user
    console.log(`registered with credentials`,userStore[id])
    return res.json({id})
})

app.post("/register-challenge",async (req,res)=>{
    const{userId}=req.body
    const user=userStore[userId]
    if(!userStore[userId]) return res.status(404).json({error:"user not found!"})
    const challengePayload=await generateRegistrationOptions({
        rpID:'localhost',
        rpName:'My Localhost Machine',
        userName:user.userName,

})
    challengeStore[userId]=challengePayload.challenge

    return res.json({options:challengePayload})

    })
app.post('/register-verify', async (req,res)=>{
    const {userId,cred}=req.body
    if(!userStore[userId]) return res.status(404).json({error:"user not found!"})
    const user=userStore[userId]
    const verificationResult=await verifyRegistrationResponse({
    expectedChallenge:challengeStore[userId],
    expectedOrigin:'http://localhost:3000',
    expectedRPID:"localhost",
    response:cred,
})
    if (!verificationResult.verified) return res.json({error:'could not verify'})
    userStore[userId].passkey=verificationResult.registrationInfo
    console.log("done verification")
    return res.json({verified:true})

    } )
app.post('/login-challenge',async (req,res)=>{
    const {userId}=req.body
    if(!userStore[userId]) return res.status(404).json({error:"user not found!"})
    
    const optns=await generateAuthenticationOptions({
        rpID:'localhost',
    })
    
    challengeStore[userId]=optns.challenge
    return res.json({options:optns});

})

app.post('/login-verify',async (req,res)=>{
    const {userId,cred}=req.body;
    if(!userStore[userId]) return res.status(404).json({error:"user not found!"})
    const {user}=userStore[userId]
    const challenge=challengeStore[userId]
    const result=await verifyAuthenticationResponse({
        expectedChallenge:challenge,
        expectedOrigin:'http://localhost:3000',
        expectedRPID:"localhost",
        response:cred,
        authenticator:user.passkey
    })
    if(!result.verified){
        return res.json({error:"something went wrong"});
    }
    return res.json({sucess:true,userId})
})


app.listen(PORT,()=>console.log(`Server running on ${PORT}`))