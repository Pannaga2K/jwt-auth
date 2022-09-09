import { AppDataSource } from "./data-source";
import { User } from "./entity/User";
import * as express from "express";
import {Request, Response} from "express";
import { RegisterDTO } from "./dto/request/request.dto";
import { Hash } from "./hash";
import { AuthenticationDTO } from "./dto/response/authentication.dto";
import { UserDTO } from "./dto/response/user.dto";
import { JWT } from "./jwt";
import { LoginDTO } from "./dto/request/login.dto";
import { EntityToDTO } from "./util/EntityToDTO";
import { RefreshTokenDTO } from "./dto/request/refreshToken.dto";
import { RefreshToken } from "./entity/RefreshToken";

const userRepository = AppDataSource.getRepository(User);

const app = express();
app.use(express.json());

app.get("/", (req: Request, res: Response) => {
    res.send("ROOT PAGE")
})

app.post("/register", async (req: Request, res: Response) => {
    const body: RegisterDTO = req.body;
    try {
        // VALIDATE
        if(body.password !== body.repeatPassword) {
            throw new Error("PASSWORD DOES NOT MATCH WITH REPEAT PASSWORD");
        }

        const user = new User();
        user.username = body.username;
        user.email = body.email;
        user.password = await Hash.hashPassword(body.password)
        await userRepository.save(user);

        const authenticationDTO: AuthenticationDTO = new AuthenticationDTO();
        const userDTO: UserDTO = EntityToDTO.userToDTO(user);

        const tokenAndRefreshToken = await JWT.generateTokenAndRefreshToken(user);
        authenticationDTO.user = userDTO;
        authenticationDTO.token = tokenAndRefreshToken.token;
        authenticationDTO.refreshToken = tokenAndRefreshToken.refreshToken;

        res.json(authenticationDTO);
    } catch(err) {
        res.json(err)
    }
})

app.post("/login", async (req: Request, res: Response) => {
    try {
        const body: LoginDTO = req.body;
        const user = await userRepository.findOneBy({email: body.email});
        if(!user) {
            throw new Error("EMAIL DOES NOT EXIST!");
        }
    
        if(!await Hash.isPasswordValid(body.password, user.password)) {
            throw new Error("INVALID PASSWORD!")
        }

        const {token, refreshToken} = await JWT.generateTokenAndRefreshToken(user);
        const authenticationDTO = new AuthenticationDTO();
        authenticationDTO.user = EntityToDTO.userToDTO(user);
        authenticationDTO.token = token;
        authenticationDTO.refreshToken = refreshToken;

        res.json(authenticationDTO);
    } catch(err) {
        res.status(500).json({
            message: err.message,
        })
    }
});

app.post("/refresh/token", async (req: Request, res: Response) => {

    try {
        const body: RefreshTokenDTO = req.body;
        // CHECK IF JWT TOKEN IS VALID
        if(!await JWT.isTokenValid(body.token)) {
            throw new Error("JWT IS NOT VALID!");
        }
        const isTokenValid = JWT.isTokenValid(body.token);
        const jwtId = JWT.getJwtId(body.token);
        const user = await userRepository.findOneBy(JWT.getJWTPayloadValueById(body.token, "id"))
    
        // CHECK IF THE USER EXISTS
        if(!user) {
            throw new Error("USER DOES NOT EXIST!");
        }
    
        // FETCH REFRESH TOKEN FROM DB
        const refreshTokenRepository = AppDataSource.getRepository(RefreshToken);
        const refreshToken = await refreshTokenRepository.findOneBy({id: body.refreshToken});
    
        // CHECK IF REFRESH TOKEN EXISTS AND IS LINKED TO JWT TOKEN
        if(!await JWT.isRefreshTokenLinkedToToken(refreshToken, jwtId)) {
            throw new Error("TOKEN DOES NOT MATCH WITH REFRESH TOKEN!");
        }
    
        // CHECK IF THE REFRESH TOKEN IS ALREADY EXPIRED
        if(await JWT.isRefreshTokenExpired(refreshToken)) {
            throw new Error("REFRESH TOKEN HAS EXPIRED!");
        }
    
        // CHECK IF REFRESH TOKEN WAS USED OR INVALIDATED
        if(await JWT.isRefreshTokenUsedOrInvalidated(refreshToken)) {
            throw new Error("REFRESH TOKEN HAS BEEN USED OR INVALIDATED");
        }
    
        refreshToken.used = true;
    
        await refreshTokenRepository.save(refreshToken);
    
        // GENERATE FRESH TOKEN AND REFRESH TOKEN
        const tokenResults = await JWT.generateTokenAndRefreshToken(user)
    
        // GENERATE AN AUTHENTICATION RESPONSE
        const authenticationDTO: AuthenticationDTO = new AuthenticationDTO();
        authenticationDTO.user = EntityToDTO.userToDTO(user);
        authenticationDTO.token = tokenResults.token;
        authenticationDTO.refreshToken = tokenResults.refreshToken;
    
        res.json(authenticationDTO);
        return authenticationDTO;
    } catch(err) {
        res.status(500).json({
            message: err.message,
        })
    }
    
})

app.listen(3000, () =>{
    console.log("SERVER HAS STARTED!");
})

AppDataSource.initialize().then(async () => {

}).catch(error => console.log(error))
