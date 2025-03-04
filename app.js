const express= require('express');
const jwt = require('jsonwebtoken');
const cookieParser= require('cookie-parser');
const bcrypt= require('bcryptjs');
const mongoose= require('mongoose');
require('dotenv').config();


const app= express();
app.use(express.json());
app.use(cookieParser());

mongoose.connect(process.env.MONGO_URI)
.then(()=>console.log('Connected to database'))
.catch((err)=>console.error(err));

const SchemaUser= new mongoose.Schema({
    username:String,
    password:String
})

const User= mongoose.model('User', SchemaUser);

app.post('/auth', async(req, res)=>{
    const {username, password}= req.body;
    if(!username || !password){
        return res.status(400).json({message:"Enter username and password"});
    }
    let user= await User.findOne({username});
    if(!user){
        const pass_hasdhed= await bcrypt.hash(password, 10);
        user= new User({username, password:pass_hasdhed});
        await user.save();
    }
    else{
        const validity= await bcrypt.compare(password, user.password);
        if(!validity){
            return res.status(400).json({message: 'Invalid credentials'});
        }
    }
    const token =jwt.sign({userId:user._id}, process.env.JWT_SECRET, {expiresIn:'1h'});
    res.cookie('token', token, {
        httpOnly:true
    })
    res.json({message:'Authentication successful'});
})

app.get('/logout', (req,res)=>{
    res.clearCookie('token');
    res.json({message:'Logged out successfully '});
})

const PORT=5000;
app.listen (PORT,()=>{
    console.log(`Server is running on port ${PORT}`);
})