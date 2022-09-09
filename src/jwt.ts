import * as jwt from "jsonwebtoken"
import { User } from "./entity/User"
import {v4 as uuidv4} from "uuid";
import { RefreshToken } from "./entity/RefreshToken";
import * as moment from "moment";
import { AppDataSource } from "./data-source";

export class JWT {
    private static JWT_SECRET_KEY = "DRAGON BALL";
    public static async generateTokenAndRefreshToken(user: User) {
        // PAYLOAD
        const payload = {
            id: user.id,
            email: user.email
        }
        const jwtID = uuidv4();
        const token = jwt.sign(payload, this.JWT_SECRET_KEY, {
            expiresIn: "1h",
            jwtid: jwtID,
            subject: user.id.toString()
        });
        const refreshToken = await this.generateRefreshTokenForUserAndToken(user, jwtID);

        return {token, refreshToken};
    }

    private static async generateRefreshTokenForUserAndToken(user: User, jwtId: string) {
        const refreshToken = new RefreshToken();
        refreshToken.user = user;
        refreshToken.jwtId = jwtId;
        refreshToken.expiryDate = moment().add(10, "d").toDate();
        const refreshTokenRepository = AppDataSource.getRepository(RefreshToken);
        await refreshTokenRepository.save(refreshToken);

        return refreshToken.id;
    }

    public static isTokenValid(token: string) {
        try {
            jwt.verify(token, this.JWT_SECRET_KEY, {ignoreExpiration: false})
            return true;
        } catch(err) {
            return false;
        }
    }

    public static getJwtId(token: string) {
        const decodedToken = jwt.decode(token);
        return decodedToken["jti"];
    }

    public static async isRefreshTokenLinkedToToken(refreshToken: RefreshToken, jwtId: string) {
        if(!refreshToken) throw new Error("REFRESH TOKEN DOES NOT EXIST!");

        if(refreshToken.jwtId !== jwtId) return false;

        return true;
    }

    public static async isRefreshTokenExpired(refreshToken: RefreshToken) {
        if(!refreshToken) throw new Error("REFRESH TOKEN DOES NOT EXIST!");

        if(moment().isAfter(refreshToken.expiryDate)) return true;

        return false;
    }

    public static async isRefreshTokenUsedOrInvalidated(refreshToken: RefreshToken) {
        return refreshToken.used || refreshToken.invalidated;
    }

    public static getJWTPayloadValueById(token: string, key: string) {
        const decodedToken = jwt.decode(token);
        return decodedToken[key];
    }

}