import { AppDataSource } from "./data-source";
import { User } from "./entity/User";
import * as express from "express";
import {Request, Response} from "express";
import { RegisterDTO } from "./dto/request/request.dto";
import { Hash } from "./hash";
import { AuthenticationDTO } from "./dto/response/authentication.dto";
import { UserDTO } from "./dto/response/user.dto";
import { JWT } from "./jwt";

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

        const userRepository = AppDataSource.getRepository(User);
        const user = new User();
        user.username = body.username;
        user.email = body.email;
        user.password = await Hash.hashPassword(body.password)
        await userRepository.save(user);

        const authenticationDTO: AuthenticationDTO = new AuthenticationDTO();
        const userDTO: UserDTO = new UserDTO();
        userDTO.id = user.id;
        userDTO.username = user.username;
        userDTO.email = user.email;

        const tokenAndRefreshToken = await JWT.generateTokenAndRefreshToken(user);
        authenticationDTO.user = userDTO;
        authenticationDTO.token = tokenAndRefreshToken.token;
        authenticationDTO.refreshToken = tokenAndRefreshToken.refreshToken;

        res.json(authenticationDTO);
    } catch(err) {
        res.json(err)
    }
})

app.listen(3000, () =>{
    console.log("SERVER HAS STARTED!");
})

AppDataSource.initialize().then(async () => {

}).catch(error => console.log(error))
