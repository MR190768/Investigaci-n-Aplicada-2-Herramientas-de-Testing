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
