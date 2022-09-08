import "reflect-metadata"
import { DataSource } from "typeorm"
import { RefreshToken } from "./entity/RefreshToken"
import { User } from "./entity/User"

export const AppDataSource = new DataSource({
    type: "mysql",
    host: "localhost",
    port: 3306,
    username: "root",
    password: "",
    database: "jwt-auth",
    synchronize: true,
    logging: false,
    entities: [User, RefreshToken],
    migrations: [],
    subscribers: [],
})
