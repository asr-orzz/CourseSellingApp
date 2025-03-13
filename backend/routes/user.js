const {Router}=require('express');
const userRouter=Router();
const {userModel, purchaseModel, courseModel}=require('../db');
const {z}=require('zod');
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');
const {userMiddleware}=require('../middlewares/userMiddleware');

userRouter.post('/signup',async function(req,res){
     const {email,password,firstName,lastName}=req.body;
        const bodySchema=z.object({
            email : z.string().email(),
            password: z.string().min(8).max(20).regex(/[A-Z]/).regex(/[a-z]/).regex(/[\W_]/),
            firstName: z.string().min(4).max(20),
            lastName: z.string().min(4).max(20)
        });
        const verify=bodySchema.safeParse(req.body);
        if(verify.success){
            const hashPassword=await bcrypt.hash(password,5);
           try{
              await userModel.create({
                    email : email,
                    password: hashPassword,
                    firstName: firstName,
                    lastName: lastName
                })
                res.json({
                    msg: "You have Signuped Successfully"
                })
            }
            catch(err){
                res.json({
                    msg : "There is Some error"
                })
            }
        }
        else{
            res.json(verify.error);
        }
})
userRouter.post('/signin',async function(req,res){
    const {email,password}=req.body;
        const bodySchema=z.object({
            email : z.string().email(),
            password: z.string().min(8).max(20).regex(/[A-Z]/).regex(/[a-z]/).regex(/[\W_]/)
        });
        const verify=bodySchema.safeParse(req.body);
        if(verify.success){
            const user= await userModel.findOne({
                email: email
            })
            const compare=await bcrypt.compare(password,user.password);
            if(compare){
                const token=jwt.sign({
                    token : user._id.toString()
                },process.env.JWT_USER_PASSWORD);
                req.headers.token=token;
                res.json({
                    token : token
                });
            }
            else{
                res.json({
                    msg : "Wrong Crendentials"
                })
            }
        }
        else{
            res.json(verify.error);
        }
})
userRouter.post('/purchase',userMiddleware,async function(req,res){
    const userId=req.headers.userId;    
    const {courseId}=req.body;
    const userBody=z.object({
        courseId: z.string()
    });

    const verify=userBody.safeParse(req.body);
    if(verify.success){
        await purchaseModel.create({
            courseId: courseId,
            userId: userId
        })
        res.json({
            msg: "Course has been purchased",
            coursePurchased: courseId
        })
    }
})
userRouter.get('/purchases',userMiddleware,async function(req,res){
    const userId=req.headers.userId; 
    const purchases= await purchaseModel.find({
        userId: userId
    })
    const courses=await courseModel.find({
        _id: {$in: purchases.map(x=>x.courseId) }
    })
    res.json({
        courses: courses
    })
})
module.exports={
    userRouter: userRouter
}