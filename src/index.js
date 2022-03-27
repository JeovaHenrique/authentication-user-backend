require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

app.use(express.json())

const User = require('./model/User')

app.get('/', (req,res) =>{
    res.status(200).json({msg: 'ok'})
})

app.get ('/user/:id',checkToken, async(req, res) => {
    
    const id = req.params.id

    const user = await User.findById(id, '-password')

    if(!user) {
        return res.status(404).json({msg: 'Usuario não encontrado'})
    }

    res.status(200).json({user})
})

function checkToken(req,res,next) {

    const authHeader = req.header['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if(!token) {
        return res.status(401).json({msg: 'Acesso negado'})
    }

    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)

        next()
    }catch(error) {
        res.status(400).json({msg: 'token invalido'})
    }
}

app.post('/auth/register', async(req, res) => {
    const {name, email, password} = req.body

    if(!name) {
        return res.status(422).json({msg: 'nome é obrigatorio'})
    }

    if(!email) {
        return res.status(422).json({msg: 'email é obrigatorio'})
    }
    if(!password) {
        return res.status(422).json({msg: 'password é obrigatorio'})
    }

    const userExist = await User.findOne({email: email})

    if(userExist) {
        return res.status(422).json({msg: 'email Já Cadastrado'})
    }

    const salt = await bcrypt.genSalt(10)
    const passwordHash = await bcrypt.hash(password, salt)

    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {

        await user.save()

        res.status(201).json({msg: 'usuario cadastrado com sucesso'})

    }catch(error) {
        console.log(error)
        res.status(500).json({
            msg: 'erro de rede, tente mais tarde',
        })
    }
})

app.post('auth/login', async(req, res) => {
    const {email, password} = req.body

    if(!email) {
        return res.status(422).json({msg: 'email é obrigatorio'})
    }
    if(!password) {
        return res.status(422).json({msg: 'password é obrigatorio'})
    }

    const user = await User.findOne({email: email})

    if(!user) {
        return res.status(404).json({msg: 'usuario não encontrado'})
    }
    const checkPassword = await bcrypt.compare(password,user.password) 

    if(!checkPassword) {
        return res.status(404).json({msg: 'senha inválida'})
    }

    try {

        const secret = process.env.SECRET

        const token = jwt.sign(
            {
                id: user.id
            },
            secret,
        )

        res.status(200).json({msg: 'autenticação bem sucedida', token})

    }catch(error) {
        console.log(error)
        res.status(500).json({
            msg: 'erro de rede, tente mais tarde',
        })
    }


})

const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose
    .connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.zjckv.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`)
    .then(() => {
        app.listen(3000)
        console.log('conectado ao bando de dados')
    })
    .catch((err) => console.log(err))