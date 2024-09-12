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



app.listen(3001,()=>{
    console.log("El servidor esta Activo en http://localhost:3001")
});
