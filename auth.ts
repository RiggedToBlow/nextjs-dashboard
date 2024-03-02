import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { getUser } from './app/lib/data';
 import bcrypt from 'bcrypt'
export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers:[credentials({
    async authorize(credentials, request) {
        const paresedCreds = z.object({email:z.string().email(), password:z.string().min(6)}).safeParse(credentials)
        if (paresedCreds.success){
            const {email,password} = paresedCreds.data
            const user = await getUser(email)
            if (!user) return null;
            const passwordMatch = await bcrypt.compare(password,user.password)
            if (passwordMatch) return user
        }
        return null
    },
  })]
});