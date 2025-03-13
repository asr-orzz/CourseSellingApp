const jwt=require('jsonwebtoken');

function userMiddleware(req,res,next){
    const token=req.headers.token;
        try{
            const verify=jwt.verify(token,process.env.JWT_USER_PASSWORD);
            req.headers.userId=verify.token;
            next();
        }
        catch(e){
            res.json({
                msg : "Sigin in First"
            })
        }
}

module.exports={
    userMiddleware
}