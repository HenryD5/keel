<script setup lang="ts">
import * as http from 'axios/unsafe/helpers';
import {
  AxiosError as ErrorAxios,
} from 'axios';
const lazy = await import('axios');
http.get('/one');
new ErrorAxios('boom');
lazy.post('/two');
</script>
