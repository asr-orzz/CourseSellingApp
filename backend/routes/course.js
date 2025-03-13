const {Router}=require('express');
const { courseModel } = require('../db');

const courseRouter= Router();

courseRouter.get('/preview',async function(req,res){
    const courses= await courseModel.find({

    })
    res.json(courses);
})

module.exports={
    courseRouter: courseRouter
}