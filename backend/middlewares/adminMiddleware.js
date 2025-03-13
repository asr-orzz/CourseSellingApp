const jwt=require('jsonwebtoken');

function adminMiddleware(req,res,next){
    const token=req.headers.token;
    try{
        const verify=jwt.verify(token,process.env.JWT_ADMIN_PASSWORD);
        req.headers.adminId=verify.token;
        next();
    }
    catch(e){
        res.json({
            msg : "Sigin in First"
        })
    }
}

module.exports={
    adminMiddleware
}