const mongoose=require('mongoose');


const Schema=mongoose.Schema;
const ObjectId=Schema.ObjectId;

const UsersSchema=new Schema({
    name:{type:String,required:true,unique:true},
    email:{
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    unique:true,
    trim: true,
    match: [/.+@.+\..+/, 'Please fill a valid email address']},
    password:{type: String,
        required: true,
        minlength: 6}
})


const UserProfileSchema=new Schema({
    name:{type:String},
    email:{type:String},
    bio:{type:String},
    profilePic:{type:String}
})


const FollowSchema=new Schema({
    user:{type: Schema.Types.ObjectId, ref: 'User'},
    followers:{type:[{
        type: Schema.Types.ObjectId,
        ref: 'User' 
    }]},
    following:{type:[{
        type: Schema.Types.ObjectId,
        ref: 'User' 
    }]}
})

const PostSchema=new Schema({
    // postId:{type: Schema.Types.ObjectId, default: mongoose.Types.ObjectId},
    content:{type:String},
    timestamp:{ type: Date, default: Date.now },
    author:{type: Schema.Types.ObjectId, ref: 'User',required:true},
    media:{type:String} 
})

const PostLikesSchema=new Schema({
    postId: { type: Schema.Types.ObjectId, ref: 'Post', required: true },
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['like', 'dislike'], required: true },
    timestamp: { type: Date, default: Date.now }
})


const CommentsSchema=new Schema({
    author:{type: Schema.Types.ObjectId, ref: 'User', required: true },
    authorName:{type:String},
    content:{type:String,required:true},
    timestamp:{type: Date, default: Date.now},
    postId:{type: Schema.Types.ObjectId, ref: 'Post', required: true}
})


const NotificationsSchema=new Schema({
type:{ type: String, enum: ['new Follower', 'new Comment','new Post'], required: true},
user:{type: Schema.Types.ObjectId, ref: 'User', required: true},
timestamp:{type: Date, default: Date.now},
fromId:{type:String,required:true},
from:{type:String},
postId:{type: Schema.Types.ObjectId, ref: 'Post'},
resource:{  type: Schema.Types.Mixed },
readStatus:{type:Boolean}
})

const FollowRequestSchema = new Schema({
    requester: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    recipient: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    status: { type: String, enum: ['pending', 'accepted', 'rejected'], default: 'pending' },
    timestamp: { type: Date, default: Date.now }
});

const FollowRequest = mongoose.model('request', FollowRequestSchema);
const Profiles=mongoose.model('profile',UserProfileSchema)
const Users=mongoose.model('user',UsersSchema)
const Follow=mongoose.model('follow',FollowSchema)
const Post=mongoose.model('post',PostSchema)
const PostLikes=mongoose.model('like',PostLikesSchema)
const Comments=mongoose.model('comment',CommentsSchema)
const Notify=mongoose.model('notification',NotificationsSchema)

module.exports={
    Users,
    Profiles,
    Follow,
    Post,
    PostLikes,
    Comments,
    Notify,
    FollowRequest
};