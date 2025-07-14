require("dotenv").config()
const jwt=require("jsonwebtoken")
const marked=require("marked")
const sanitizeHTML = require("sanitize-html")
const bcrypt = require("bcrypt")
const cookieparser = require("cookie-parser")
const express = require("express")
const { use } = require("react")
const db= require("better-sqlite3")("app.db")
db.pragma("journal_mode = WAL")


//database setup 

const createTables=db.transaction(()=>{
    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS user(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
        `
    ).run()


    db.prepare(`
        CREATE TABLE IF NOT EXISTS post(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            createdDate TEXT,
            title STRING NOT NULL,
            body TEXT NOT NULL,
            authorid INTEGER,
            FOREIGN KEY (authorid) REFERENCES user(id)
            )
        
        `).run()
})

createTables()
const app = express()

app.set("view engine","ejs")
app.use(express.urlencoded({extended:false}))
app.use(express.static("public"))
app.use(cookieparser())

app.use(function(req,res,next){
    //markdown function
    res.locals.filteringhtml = function(content){
        return sanitizeHTML(marked.parse(content),{
            allowedTags:["p","br","ul","li","ol","strong","bold","i","em","h1","h2","h3","h4","h5","h6"],
            allowedAttributes: {}
        })
    }

    res.locals.errors=[]
    //check for cookies
    try{
        const cookied = jwt.verify(req.cookies.ourapp,process.env.JWTSECRET)
        req.user = cookied
    }catch(err){
        req.user = false

    }

    res.locals.user = req.user
    console.log(req.user)

    next()
})




//routes for different recieving pages


app.get("/",(req,res)=>{
    if(req.user) {
        const poststatemnet = db.prepare("SELECT* FROM post WHERE authorid = ? ORDER BY createdDate DESC")
        const posts = poststatemnet.all(req.user.userid)
        return res.render("dashboard",{posts})
    }
    res.render("homepage")
})

app.get("/login",(red,res)=>{
    res.render("login")
})

app.get("/logout",(req,res)=>{
    res.clearCookie("ourapp")
    res.redirect("/")
})

app.post("/login",(req,res)=>{
    let errors = []
    
    if(typeof req.body.username !== "string") req.body.username  =""
    if(typeof req.body.password !== "string") req.body.password  =""

    if(req.body.username.trim()== "") errors= ["invalid username or password"] // can use const errors and errors.push but produces multiple errors if multiple fields balnk
    if(req.body.password== "") errors = ["invalid username or password"]

    if(errors.length){
        return res.render("login",{errors})
    }

    const userInQuestionStatement = db.prepare("SELECT * FROM user WHERE USERNAME = ?") //what  username?
    const userInQuestion= userInQuestionStatement.get(req.body.username) // the one the user inputs

    if(!userInQuestion){
        errors = ["Invalid username or pasword"]
        return res.render("login",{errors})
    }

    const matchornot = bcrypt.compareSync(req.body.password,userInQuestion.password)
    if (!matchornot){
        errors = ["Invalid username or pasword"]
        return res.render("login",{errors})
    }
    // gives a cookies and redirects to homepage 
    const tokenvalue= jwt.sign({exp: Math.floor(Date.now()/1000) + 60*60*24,userid:userInQuestion.id, username:userInQuestion.username},process.env.JWTSECRET )


    res.cookie("ourapp",tokenvalue,{
        httpOnly: true,
        secure: true,
        sameSite:"strict",
        maxAge: 1000 * 60 * 60 * 24 
    })
    res.redirect("/")
})

function logged(req,res,next){
    if (req.user){
        return next()
    }
    return res.redirect("/")
}


app.get("/create-post",logged,(req,res)=>{ //express allows functions to be run one after the other
res.render("create-post")

})

function sharedpostvalidation(req){
    const errors = []

    if(typeof req.body.title !== "string") req.body.title = ""
    if (typeof req.body.body !== "string") req.body.title = ""
    
    // trim htmlto stop malware this is the front ends job ......
    //just to be safe
    req.body.title = sanitizeHTML(req.body.title.trim(),{allowedTags: [],allowedAttributes:{}})
    req.body.body = sanitizeHTML(req.body.body.trim(),{allowedTags: [],allowedAttributes:{}})

    if(!req.body.title) errors.push("you must provide a title")
    if(!req.body.body) errors.push("you must provide a body")
    return errors
}

app.get("/edit-post/:id",logged,(req,res)=>{
    const statement=db.prepare("SELECT * FROM post WHERE id = ?")
    const post = statement.get(req.params.id)

    if (!post){
        return res.redirect("/")
    }

    if (post.authorid !== req.user.userid){
        return res.redirect("/")
    }

    
    
    res.render("edit-post",{post,})


})


app.post("/edit-post/:id",logged,(req,res)=>{
    const statement=db.prepare("SELECT * FROM post WHERE id = ?")
    const post = statement.get(req.params.id)

    if (!post){
        return res.redirect("/")
    }

    if (post.authorid !== req.user.userid){
        return res.redirect("/")
    }


    const errors=  sharedpostvalidation(req)

    if (errors.length){
        return res.render("edit-post",{errors})
    }

    const updatestatement = db.prepare("UPADTE post SET title = ?,body = ? WHERE id = ?")
    updatestatement.run(req.body.title,req.body.body,req.params.id)
    res.redirect(`/post/${req.params.id}`)
})


app.post("/delete-post/:id",logged,(req,res)=>{
    const statement=db.prepare("SELECT * FROM post WHERE id = ?")
    const post = statement.get(req.params.id)

    if (!post){
        return res.redirect("/")
    }

    if (post.authorid !== req.user.userid){
        return res.redirect("/")
    }

    const deletestatement = db.prepare(" DELETE FROM post WHERE id = ?")
    deletestatement.run(req.params.id)

    res.redirect("/")

})


app.get("/post/:id",(req,res)=>{
    const statement =db.prepare("SELECT post.*,user.username FROM post INNER JOIN user ON post.authorid = user.id WHERE post.id = ?")
    const post = statement.get(req.params.id)

    if (!post){
        return res.redirect("/")
    }
    const isAuthor = post.authorid === req.user.userid

    res.render("single-post",{post,isAuthor})

})


app.post("/create-post",logged,(req,res)=>{ 
    const errors = sharedpostvalidation(req)

    if (errors.length){
        return res.render("create-post",{errors})
    }
//more saving into database
    const thisstatement=db.prepare("INSERT INTO post (title,body,authorid,createdDate) VALUES (?,?,?,?)")
    const result = thisstatement.run(req.body.title,req.body.body,req.user.userid,new Date().toISOString())

    const getpoststatement = db.prepare("SELECT * FROM post WHERE ROWID = ?")
    const posted = getpoststatement.get(result.lastInsertRowid)

    res.redirect(`/post/${posted.id}`)

})


//creating users and passwords with restraints 
app.post("/register",(req,res) =>{
    const errors = []
    
    if(typeof req.body.username !== "string") req.body.username  =""
    if(typeof req.body.password !== "string") req.body.password  =""
    
    req.body.username=req.body.username.trim()

    if(!req.body.username) errors.push("you must have a username youidiot")
    if (req.body.username && req.body.username.length < 3) errors.push("username too short")
    if (req.body.username && req.body.username.length > 10) errors.push("username too long")
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("can only have letters and numbers")

//checking usernames againnnnnn

    const usernameStatement = db.prepare("SELECT * FROM user WHERE username = ?")
    const usercheck = usernameStatement.get(req.body.username)

    if (usercheck) errors.push("username already exits")


    if(!req.body.password) errors.push("you must have a password youidiot")
    if (req.body.password && req.body.password.length < 8) errors.push("password too short")
    if (req.body.password && req.body.password.length > 16) errors.push("passowrd too long")



    if (errors.length){
        return res.render("homepage",{errors})
    }

    //saving in the database
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password,salt)
    const statement=db.prepare("INSERT INTO user (username,password) VALUES (?, ?)")
    const result = statement.run(req.body.username,req.body.password)
    
    const lookupStatement = db.prepare("SELECT * FROM user WHERE ROWID =?")
    const ouruser = lookupStatement.get(result.lastInsertRowid)


    //different homepages for logged in users
    const tokenvalue= jwt.sign({exp: Math.floor(Date.now()/1000) + 60*60*24,userid:ouruser.id, username:ouruser.username},process.env.JWTSECRET )


    res.cookie("ourapp",tokenvalue,{
        httpOnly: true,
        secure: true,
        sameSite:"strict",
        maxAge: 1000 * 60 * 60 * 24 
    })
    res.redirect("/")
})

app.listen(5174)