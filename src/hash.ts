import * as bcrypt from "bcrypt";

export class Hash {
    public static async hashPassword(password: string) {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        return hashedPassword;
    }
}