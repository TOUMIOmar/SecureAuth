const jwt=require('jsonwebtoken')


/* Middleware that verify token */
const userMiddleware=async(req,res,next)=>{
    try {
        const token=req.headers.token
        if(!token){
            res.json({msg:"You are not authorized"})
        }
        else{
            jwt.verify(token,process.env.JWT_SECRET,(err,data)=>{
                if(err){
                    res.json({msg:"You are not authorized"})
                }
                else{
                    req.body.user_id=data.id
                    console.log(data)
                    next()
                }
            })
        }
    } catch (error) {
        res.json({msg:"Something went wrong during user Middleware!",error})
    }
}

module.exports=userMiddleware