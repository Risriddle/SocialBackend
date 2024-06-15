const express=require('express')
const session = require('express-session');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const socketIo = require('socket.io');
const app=express()
const server = http.createServer(app);
const io = socketIo(server);
const {sendMail,generateOtp}=require('./mail.js')


app.use(express.json());
app.use(express.urlencoded({ extended: true }));

require('dotenv').config();

const port=process.env.PORT
const sec=process.env.SECRET
// Configure session middleware
app.use(session({
    secret: sec, // Change this to a secure secret key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set secure: true if using HTTPS
}));

//database conf
const mongoose=require('mongoose');
const uri=process.env.MONGODB_URI;

mongoose.connect(uri,{
    useNewUrlParser:true,
    useUnifiedTopology:true
})
.then(()=>console.log("connected to mongodb"))
.catch(err=>{
    console.log("failed to connect to mongo",err);   
})
const {Users,Profiles,Follow,Post, PostLikes,Comments,Notify,FollowRequest}=require('./models.js')





// Setup connection event
io.on('connection', (socket) => {
    console.log('a user connected');
    
    // Handling user-specific events (e.g., joining a room based on user ID)
    socket.on('join', (userId) => {
        socket.join(userId);
    });
});

app.get('/',(req,res)=>{
    res.send("hello there");
})


const JWT_SECRET = process.env.JWT_SECRET; // Replace with your secure secret

// Helper function to generate JWT
const generateToken = (user) => {
    return jwt.sign({ id: user.id, email: user.email,name:user.name }, JWT_SECRET, { expiresIn: '1h' });
};


//registration
var otp
app.post('/register',async(req,res)=>{
    const name=req.body.name;
    const username = await Users.findOne({ name: name });
    console.log(username,"===========")
    if (username){
    res.send("this name is taken. enter another")
    }
    else{
    const password=req.body.password;
    const email=req.body.email
    otp=generateOtp()
    console.log(otp,"seny")
    req.session.otp = otp; // Store OTP in session
    req.session.email=email;
    req.session.name =name; // Store user data in session
    req.session.password=password;

    sendMail(email,otp).then(success => {
        if (success) {
            res.send('OTP sent successfully.');
        } else {
            res.status(500).send('Failed to send OTP.');
        }
    });
    }
})

//email varification
app.post('/verify-otp', async(req, res) => {
    const otp = req.body.otp;
    console.log(otp,req.session.otp)
    // Check if email and OTP match those stored in session
    if (req.session.email){
    if (req.session.otp === otp) {
        // req.session.destroy(); // Clear session after successful verification
        // res.send('OTP verified successfully.');
        //store registered user in db
        try{
            const hashedPass= await bcrypt.hash(req.session.password, 10); // 10 is the salt rounds
         
          const newUser=new Users({
            name:req.session.name,
            password:hashedPass,
            email:req.session.email
          });
          console.log(newUser)
          const savedUser = await newUser.save();
        //   res.render('login',{msg:"Registration Successful. Now Log in"})
        res.send("successful login")
        }
        catch (err) {
          res.status(400).json({ error: err.message });
        } 
    } else {
        res.status(400).send('Invalid OTP.');
    }}
});

//login
app.post('/login',async(req,res)=>{
    const email=req.body.email;
    const password=req.body.password;

    try {
        const user = await Users.findOne({ email: email });
        if (!user) {
            // return res.render('login', { msg: 'User not found' });
            return res.send("user not found")
        }
  
        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
            // res.send("logged in!!")

            const token = generateToken(user);
            res.send({ token });
            
        } else {
            // return res.render('login', { msg: 'Invalid username or password' });
            return res.send("not logged in")
        }
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).send('Internal Server Error');
    }
  });


// Middleware to protect routes(tokens for each user)
const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    console.log(token)
    if (!token) {
        return res.sendStatus(401); // Unauthorized
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403); // Forbidden
        }

        req.user = user;
        next();
    });
};



// Configure Multer for file uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = 'uploads/';
        if (!fs.existsSync(uploadPath)){
            fs.mkdirSync(uploadPath);
        }
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

//edit or upload profile
const upload = multer({ storage: storage });
app.post('/uploadUserProfile',authenticateJWT, upload.single('profileImage'), async (req, res) => {
    // const { name, email } = req.body;
     const bio=req.body.bio
     const name=req.body.name
     
    if (!req.file) {
        return res.status(400).send('No file uploaded.');
    }
    const user = await Users.findOne({ email: req.user.email });
       console.log(req.file.path,"-----------------------")
    // Create a new user with the provided data
    const newUserProfile = new Profiles({
        name:name,
        email:user.email,
        bio:bio,
        profilePic:req.file.path // Save file path in the database
    });
   
    const duplicate=await Profiles.find({email:user.email})
    
    // console.log(duplicate[0]._id)
    console.log(duplicate,"dupppppppp0000000000000000000000000000000")
    if (duplicate.length!=0){
        newUserProfile._id = duplicate[0]._id;
        const d=await Users.findOne({name:name})
        console.log(d,"===============",duplicate[0])
        if(duplicate[0].name!==name){
            if(d){
            if(d.name===name){
            console.log("name taken reset another")
            return res.send("taken!!!!!!!!!!!")
        }}
        else{
        await Users.findOneAndUpdate({email:user.email},{name:name})}
        await Profiles.replaceOne({_id:duplicate[0]._id},newUserProfile)
            res.send("profile updated")
        }
        else{
        // await Users.findOneAndUpdate({email:user.email},{name:name})       
         await Profiles.replaceOne({_id:duplicate[0]._id},newUserProfile)
            res.send("profile updated")}
      
}
       
    else{
        const d=await Users.findOne({name:name})
        console.log(d,"==============")
        if (name!=user.name){
        if(d){
            res.send("name taken reset another!!!!!!!1")
        }
        await Users.findOneAndUpdate({email:user.email}, { $set: { name:name} })
    
    }
        console.log(user.email,"emaillllllllllllllllllllllll")
      await newUserProfile.save();
    res.send('User profile uploaded successfully.');
    }
});


//for viewing user profiles
app.get('/user/:name', async (req, res) => {
    const user = await Profiles.findOne({name:req.params.name});
    if (!user) {
        return res.status(404).send('User not found.');
    }
    res.json(user);
});




// //to follow and unfollow users
// app.get('/follow/:name',authenticateJWT, async (req, res) => {
//     const followId=await Users.findOne({name:req.params.name})
//     console.log(req.user.id,"--------main user",req.user.name)
//     console.log(followId.id,"follow",followId.name)
//     const MainUser=req.user.id
//     const follow=followId.id
//     const exist=await Follow.findOne({name:MainUser})
//     const existF=await Follow.findOne({name:follow})
//     if (!exist){
//     const addData=new Follow({
//         name:MainUser,
//         followers:[],
//         following:[follow]
//     })
//     await addData.save();
// }
//     else{
//         if (!exist.following.includes(follow)) {
//             exist.following.push(follow);
//             await exist.save();
//             console.log('Updated existing follow document');
//         } else {
//             console.log('User is already followed');
//         }
//     }
//     if (!existF){
//         const addData=new Follow({
//             name:follow,
//             followers:[MainUser],
//             following:[]
//         })
//         await addData.save();
//     }
//         else{
//             if (!existF.following.includes(MainUser)) {
//                 existF.following.push(MainUser);
//                 await existF.save();
//                 console.log('Updated existing follow document');
//             } else {
//                 console.log('User is already followed');
//             }
//         }
      
//     res.send("updated")
//     console.log("saved")

// });



app.post('/follow/:name', authenticateJWT, async (req, res) => {
    try {
        const recipientUser = await Users.findOne({ name: req.params.name });
        if (!recipientUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        const followRequest = new FollowRequest({
            requester: req.user.id,
            recipient: recipientUser._id
        });

        await followRequest.save();
        
        // Emit follow request to the recipient
        io.to(recipientUser._id.toString()).emit('followRequest', followRequest);

        res.json({ message:"follow request sent"});
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'An error occurred' });
    }
});


app.post('/acceptFollow/:requestId', authenticateJWT, async (req, res) => {
    try {
        const followRequest = await FollowRequest.findById(req.params.requestId);

        if (!followRequest || followRequest.recipient.toString() !== req.user.id) {
            return res.status(404).json({ error: 'Follow request not found' });
        }

        followRequest.status = 'accepted';
        await followRequest.save();

        // Update follow relationships
        let recipientFollow = await Follow.findOne({ user: followRequest.recipient });
        if (!recipientFollow) {
            recipientFollow = new Follow({ user: followRequest.recipient });
        }
        if (!recipientFollow.followers.includes(followRequest.requester)) {
            recipientFollow.followers.push(followRequest.requester);
        }
        await recipientFollow.save();

        let requesterFollow = await Follow.findOne({ user: followRequest.requester });
        if (!requesterFollow) {
            requesterFollow = new Follow({ user: followRequest.requester });
        }
        if (!requesterFollow.following.includes(followRequest.recipient)) {
            requesterFollow.following.push(followRequest.recipient);
        }
        await requesterFollow.save();

        // Emit follow acceptance to the requester
        io.to(followRequest.requester.toString()).emit('followAccepted', followRequest);

        res.json({ message: 'Follow request accepted' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'An error occurred' });
    }
});

app.post('/rejectFollow/:requestId', authenticateJWT, async (req, res) => {
    try {
        const followRequest = await FollowRequest.findById(req.params.requestId);

        if (!followRequest || followRequest.recipient.toString() !== req.user.id) {
            return res.status(404).json({ error: 'Follow request not found' });
        }

        followRequest.status = 'rejected';
        await followRequest.save();

        // Emit follow rejection to the requester
        io.to(followRequest.requester.toString()).emit('followRejected', followRequest);

        res.json({ message: 'Follow request rejected' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'An error occurred' });
    }
});


app.get('/unfollow/:name',authenticateJWT, async (req, res) => {
    const unfollowId=await Users.findOne({name:req.params.name})
    console.log(req.user.id,"--------main user",req.user.user)
    console.log(unfollowId.id,"unfollow",unfollowId.name)
    const MainUser=req.user.id
    const unfollow=unfollowId.id
    await Follow.updateOne(
        { user:MainUser },
        { $pull: { following: unfollow } }
    )
    await Follow.updateOne(
        { user:unfollow },
        { $pull: { followers: MainUser } }
    )
    res.send("unfollowed")

});


//list of followers and following
app.get('/listFollow/:name',async(req,res)=>{
const nameId=await Users.findOne({name:req.params.name})
const disp=await Follow.findOne({name:nameId._id})
console.log(nameId,disp)
const following=[]
const followers=[]
for (const entry of disp.following)
{
console.log(entry)
const name= await Users.findOne({_id:entry})
console.log(name.name)
following.push(name.name)
}
for (const entry of disp.followers)
    {
    console.log(entry)
    const name= await Users.findOne({_id:entry})
    console.log(name.name)
    followers.push(name.name)
    }
    console.log(followers,following)
    const sendData={"followers":followers,"following":following}
    res.json(sendData)
})

//save media of posts
const postMediaStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'post_media/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const postMediaUpload = multer({ storage: postMediaStorage });

//creating post
app.post('/createPost',authenticateJWT, postMediaUpload.single('media'),async(req,res)=>{
    const content=req.body.content
    const author=req.user.id
    const media=req.file ? req.file.path : null;

    const newPost=new Post({
        content:content,
        author:author,
        media:media
    })

    await newPost.save()
    const followRecord = await Follow.findOne({ user: author }).populate('followers');
        if (followRecord && followRecord.followers.length > 0) {
            // Create notifications for each follower
            const notifications = followRecord.followers.map(follower => ({
                type: 'new Post',
                user: follower._id,
                fromId: author,
                from: req.user.name,
                postId: newPost._id,
                readStatus: false
            }));

            await Notify.insertMany(notifications);

            // Emit WebSocket events to each follower
            notifications.forEach(notification => {
                io.to(notification.user.toString()).emit('notification', notification);
            });
        }

        res.send(newPost);
    } )
//reading post(PUBLIC TO ALL)
app.get('/readPost/:name',postMediaUpload.single('media'),async(req,res)=>{
    const name=req.params.name
    const nameId=await Users.findOne({name:name})
    const showPost=await Post.find({author:nameId._id})
    res.send(showPost)
})

//updating posts
app.put('/updatePost/:postId',authenticateJWT,postMediaUpload.single('media'),async(req,res)=>{
    const content=req.body.content
    const media=req.file ? req.file.path : null;
    const postId=req.params.postId
    await Post.findOneAndUpdate({ _id: postId }, 
    { $set: { content: content, media: media } }, 
    { new: true } 
)
res.send("updated")
})


//deleting posts
app.delete('/deletePost/:postId',authenticateJWT,async(req,res)=>{
     const postId=req.params.postId
    await Post.findOneAndDelete({ _id: postId } )
res.send("deleted")
})

//liking and unliking posts
app.get('/likedislikePost/:postId/:type',authenticateJWT,async(req,res)=>{

    const postId=req.params.postId;
    const user=req.user.id;
    const type=req.params.type;

    if (type==='like'){
        const existLike=await PostLikes.findOne({postId:postId,user:user,type:'like'})
        if (existLike){
            res.send("already liked")
        }
        else{
            const addLike=new PostLikes({
                postId:postId,
                user:user,
                type:'like'
            })
            addLike.save()
            res.send("liked")
        }
    }
    if (type==='dislike'){
        const existdisLike=await PostLikes.findOne({postId:postId,user:user,type:'dislike'})
        if (existdisLike){
            res.send("already disliked")
        }
        else{
            const adddisLike=new PostLikes({
                postId:postId,
                user:user,
                type:'like'
            })
            adddisLike.save()
            res.send("disliked")
        }
    }

})


//counting likes and dislikes
app.get('/posts/:postId', async (req, res) => {
    try {
        const postId = req.params.postId;

        // Count likes
        const likeCount = await PostLikes.countDocuments({ postId: postId, type: 'like' });

        // Count dislikes
        const dislikeCount = await PostLikes.countDocuments({ postId: postId, type: 'dislike' });

        // Send response
        res.json({ likes: likeCount, dislikes: dislikeCount });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});



//comment on a post
app.post('/createComment/:postId',authenticateJWT,async(req,res)=>{

const author=req.user.id;
const postId=req.params.postId;
const content=req.body.content;
console.log(content,"--------------------")
const postUser=await Post.findOne({_id:postId})



const addComment=new Comments({
    authorName:req.user.name,
    author:author,
    postId:postId,
    content:content
})

const newNotification=new Notify({
    type:'new Comment',
    user:postUser.author,
    fromId:author,
    from:req.user.name,
    postId:postId,
    readStatus:false,
    resource:addComment._id
})
await newNotification.save()
await addComment.save()
io.to(postUser.author.toString()).emit('notification', newNotification);

res.json(newNotification)

})



//reading comments
app.get('/readComments/:postId',async(req,res)=>{
    const postId=req.params.postId;
    const findComments=await Comments.find({postId:postId})
    res.send(findComments)
})

//update comments
app.put('/updateComments/:commentId',authenticateJWT,async(req,res)=>{
const commentId=req.params.commentId;
const user=req.user.id
const auth=await Comments.findOne({_id:commentId})
console.log(auth.author.toHexString(),"===========",user)
if(user===auth.author.toHexString()){
const updatedComment=req.body.content
await Comments.findOneAndUpdate({_id:commentId},{ $set: {content:updatedComment} })
const newComment=await Comments.findOne({_id:commentId})
res.json(newComment)
}
else{
    res.send("unauthorized")
}
})


//delete comments
app.delete('/deleteComments/:commentId',authenticateJWT,async(req,res)=>{
    const commentId=req.params.commentId;
    const user=req.user.id
const auth=await Comments.findOne({_id:commentId})
console.log(auth.author.toHexString(),"===========",user)
if(user===auth.author.toHexString()){
    await Comments.findOneAndDelete({_id:commentId})
    res.send("deleted")
}
else{
    res.send("unauthorized")
}
})

//get posts of users followed on feed
app.get('/userFeed',authenticateJWT, postMediaUpload.single('media'),async(req,res)=>
{
 const user=req.user.id
    const followedUsers=await Follow.findOne({name:user})
    // console.log(followedUsers.following)
    const postsSend=[]

        // Fetch posts from all followed users in one query
        const posts = await Post.find({ author: { $in: followedUsers.following } }).sort({ createdAt: -1 });
        postsSend.push(posts)
   
res.json(postsSend)
})


//pagination(IMPLEMENT IN USER FEED)
// app.get('/posts', async (req, res) => {
//     try {
//         const { limit = 10, cursor } = req.query;

//         // Prepare query based on cursor or offset
//         const query = cursor ? { _id: { $lt: cursor } } : {};

//         // Fetch posts from database
//         const posts = await Post.find(query)
//                                 .sort({ _id: -1 }) // Sort by descending ID or timestamp
//                                 .limit(parseInt(limit, 10)); // Convert limit to integer

//         // Determine the next cursor for pagination
//         const nextCursor = posts.length > 0 ? posts[posts.length - 1]._id : null;

//         // Prepare response object
//         res.json({
//             posts,
//             nextCursor,
//             hasMore: posts.length === parseInt(limit, 10)
//         });
//     } catch (error) {
//         console.error(error);
//         res.status(500).json({ message: 'Internal server error' });
//     }
// });



//post filtering

//filter by author of post
app.get('/postSearchName/:name',authenticateJWT,postMediaUpload.single('media'),async(req,res)=>{
    const name=req.params.name
    const nameId=await Users.findOne({name:name})
    const user=req.user.id
    const followedUsers=await Follow.findOne({name:user})
    const postsSend=[]
    if (followedUsers.following.includes(nameId._id)){
        const posts = await Post.find({ author: { $in: nameId._id } }).sort({ createdAt: -1 });
        postsSend.push(posts)
    }
res.json(postsSend)

})

//filtering posts by hashtags
app.get('/postSearchHashtag/:hashtag',authenticateJWT,postMediaUpload.single('media'),async(req,res)=>{
    const hashtag=req.params.hashtag
    const user=req.user.id
    const followedUsers=await Follow.findOne({name:user})
    // console.log(followedUsers.following)
    const postsSend=[]
        // Fetch posts from all followed users in one query
        const posts = await Post.find({
            $and: [
                { author: { $in: followedUsers.following } }, // Filter by followed users
                { content: { $regex: `#${hashtag}\\b`, $options: 'i' } } // Filter by hashtag in content
            ]
        }).sort({ createdAt: -1 });    postsSend.push(posts)
   
res.json(postsSend)
   
})



server.listen(port,()=>{
    console.log("app available on http://localhost:5000")
})

