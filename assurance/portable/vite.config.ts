import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';
import {fileURLToPath} from 'node:url';
export default defineConfig({root:fileURLToPath(new URL('./client',import.meta.url)),plugins:[react()],resolve:{alias:{'@':fileURLToPath(new URL('..',import.meta.url))}},build:{outDir:'../dist',emptyOutDir:true}});
