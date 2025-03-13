const {Router}=require('express');
const adminRouter=Router();
const {adminModel,courseModel}=require('../db');
const {z}=require('zod');
const bcrypt=require('bcrypt');
const jwt=require('jsonwebtoken');
const {adminMiddleware}=require('../middlewares/adminMiddleware');

adminRouter.post('/signup',async function(req,res){
    const {email,password,firstName,lastName}=req.body;
    const bodySchema=z.object({
        email : z.string().email(),
        password: z.string().min(8).max(20).regex(/[A-Z]/).regex(/[a-z]/),
        firstName: z.string().min(4).max(20),
        lastName: z.string().min(4).max(20)
    });
    const verify=bodySchema.safeParse(req.body);
    if(verify.success){
        const hashPassword=await bcrypt.hash(password,5);
       try{
          await adminModel.create({
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
adminRouter.post('/signin',async function(req,res){
    const {email,password}=req.body;
    const bodySchema=z.object({
        email : z.string().email(),
        password: z.string().min(8).max(20).regex(/[A-Z]/).regex(/[a-z]/.regex(/[\W_]/))
    });
    const verify=bodySchema.safeParse(req.body);
    if(verify.success){
        const user= await adminModel.findOne({
            email: email
        })
        const compare=await bcrypt.compare(password,user.password);
        if(compare){
            const token=jwt.sign({
                token : user._id.toString()
            },process.env.JWT_ADMIN_PASSWORD);
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
adminRouter.post('/course',adminMiddleware,async function(req,res){
    const {title,description,price,imageUrl}=req.body;
    const adminId=req.headers.adminId;
    const reqcourseBody=z.object({
        title : z.string(),
        description: z.string(),
        price : z.number(),
        imageUrl: z.string()
    })
    const verify=reqcourseBody.safeParse(req.body);
    if(verify.success){
       const course= await courseModel.create({
            title: title,
            description: description,
            price: price,
            imageUrl: imageUrl,
            creatorId: adminId
        })
        res.json({
            msg : "Course Has been Created",
            courseId: course._id
        })
    }
    else{
        res.json(verify.error);
    }
})
adminRouter.put('/course',adminMiddleware,async function(req,res){
    const {title,description,price,imageUrl,courseId}=req.body;
    const adminId=req.headers.adminId;
    const reqcourseBody=z.object({
        title : z.string(),
        description: z.string(),
        price : z.number(),
        imageUrl: z.string(),
        courseId: z.string()
    })
    const verify=reqcourseBody.safeParse(req.body);
    if(verify.success){
      await courseModel.updateOne(
        {
            _id: courseId,
            creatorId: adminId
        },
        {
            title: title,
            description: description,
            price: price,
            imageUrl: imageUrl
        })
        res.json({
            msg : "Course Has been Updated"
        })
    }
    else{
        res.json(verify.error);
    }
}
)
adminRouter.get('/course',adminMiddleware,async function(req,res){
    const adminId=req.headers.adminId;
    try{
        const courses=await courseModel.find({
            creatorId: adminId
        })
        res.json(courses);
    }
    catch(e){
        res.json({
            msg : "Something Went Wrong"
        })
    }
   
})

module.exports={
    adminRouter: adminRouter
}