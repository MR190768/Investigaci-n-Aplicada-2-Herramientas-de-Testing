import express from "express"; //importa express
import fs from "fs";           //permite escritura y lectura de JSON
import bodyParser from "body-parser"; //la da la capicidad de enteder estructuras JSON
import bcrypt from 'bcrypt'; //encriptacion de datos
import jwt from "jsonwebtoken"; //generador de tokens

const app =express();
const skey="clavesecretatamporal"; //secretKEY
var contador; //cantoador de sesiones
let tokenblacklist=[]; //lista negra de tokens
app.use(bodyParser.json()); 

//Funion que permite leer el JSON que se esta utilisando como db
const leerData=()=>{
    const datos =fs.readFileSync("./db.json");
    return JSON.parse(datos);
};

//Funcion que recibe un dato que sera agregado al JSON que se esta utilizando como db
const escribirData=(dato)=>{
    fs.writeFileSync("./db.Json",JSON.stringify(dato));
};


//Metodo POST registrar: primeor lee el JSoN db luego lee el nuevo Usuario, encripta la contraseña
//agrega el nuevo usario y actualiza el JSON db
app.post("/api/register",(req,res)=>{
    
    const UsersDB=leerData();
    const datosReq=req.body;
    if(UsersDB.users.find((users)=>users.username == datosReq.username)){
        res.status(400).send({status:"FAIL",message:"Usuario ya existe"});
    }
    else{
    bcrypt.hash(datosReq.password,2,(error,hash)=>{
        if(error){
            res.status(500).send({status:"FAIL",message:"El servidor no pudo procesar su solicitud"});
        }
        else{
            const newUsuario={
                id: UsersDB.users.length + 1,
                username: datosReq.username,
                password:hash,
                email:datosReq.email,
                status:"INACTIVO"
            };
            UsersDB.users.push(newUsuario);
            escribirData(UsersDB);
            res.status(201).send({status:"OK",message:"Usuario registrado con exito"});
        }
    })
    }
});

//Metodo POST Login: lee el JSON db luego lee los datos recibidos 
//posteriormente busca si los datos existen 
//luego que estos coicidan con el usuario
//si todo resulto se cambia el estatus del usario y se le asigna un token de sesion
app.post("/api/login",(req,res)=>{
    
    const lectura=leerData();
    const datosReq=req.body;
    const userN=lectura.users.find((users)=>users.username == datosReq.username);
    const index=lectura.users.findIndex((users)=>users.username == datosReq.username);
    if(userN.status=="ACTIVO"){
        res.status(400).send({status:"FAIL",message:"Usuario ya esta conectado"});
    }
    else{
        bcrypt.compare(datosReq.password,userN.password,(error,result)=>{
            if(error){
                res.status(500).send({status:"FAIL",message:"El servidor no pudo procesar su solicitud"});
            }
            else if(result){
                const payload={
                    username:datosReq.username,
                    numSesion:contador
                };
                contador++;
                const tokenA=jwt.sign(payload,skey);
                lectura.users[index]={
                    id: userN.id,
                    username: userN.username,
                    password:userN.password,
                    email:userN.email,
                    status:"ACTIVO"
                }
                escribirData(lectura);
                res.status(200).send({status:"OK",message:"Se logueo correctamente",Authorization:tokenA});
            }
            else{
                res.status(400).send({status:"FAIL",message:"Usuario o contraseña invalida"});
            }
    
        });
    }  
    
});

//Metodo POST logout: lee el token de sesion recibido 
//verifica el token sea veridico
//si es asi invalida el token agregandolo a una blacklist
//si todo resulto se cambia el estatus del usario a INACTIVO 
app.post("/api/logout",(req,res)=>{
    try{
    const datosReq=req.body;
    const datosProtegido=jwt.verify(datosReq.Authorization,skey);
    tokenblacklist.push(datosReq.Authorization);

    const lectura=leerData();
    const userN=lectura.users.find((users)=>users.username == datosProtegido.username);
    const index=lectura.users.findIndex((users)=>users.username == datosProtegido.username);
    lectura.users[index]={
        id: userN.id,
        username: userN.username,
        password:userN.password,
        email:userN.email,
        status:"INACTIVO"
    }
    escribirData(lectura);

    res.status(200).send({status:"OK",message:"Deslogueado correctamente"});
    
    }
    catch(error){
        res.status(400).send({status:"FAIL",message:"token no valido"});
    }
});


app.listen(3001,()=>{
    console.log("El servidor esta Activo en http://localhost:3001")
});

//Metodo GET Ver protegidos: lee el token de sesion recibido 
//revisa que el token este activo
//luego verifica el token sea veridico
//si todo resulto le da permiso a ver contenido protegido
app.get("/api/protected-resource",(req,res)=>{
    try{
        const datosReq=req.body;
        if(tokenblacklist.includes(datosReq.Authorization)){
        res.status(400).send({status:"FAIL",message:"token expirado"});
        }
        else{
            const datosProtegido=jwt.verify(datosReq.Authorization,skey);
            const lectura=leerData();
            res.status(200).send(lectura);
        }
    }
    catch(error){
        res.status(400).send({status:"FAIL",message:"token no valido"});
    }
});

